import { sanitizeSensitiveData } from '../services/privacy.service.js';
import { extractEntities } from '../services/entityExtraction.service.js';
import {
  evaluateScamRules,
  determineScamType,
  generateSafetyAdvice,
  extractEvidenceExcerpts,
} from '../services/scamDetection.service.js';
import { analyzeSenderIntel } from '../services/phoneIntel.service.js';
import { scanUrl } from '../services/urlScanner.service.js';
import { calculateRiskScore } from '../utils/riskScoring.js';
import { analyzeWithGemini } from '../services/gemini.service.js';
import { combineEngineResults } from '../utils/engineCombiner.js';

/**
 * Controller for POST /api/analyze
 * Orchestrates entity extraction, privacy sanitization, rule evaluation, Gemini AI reasoning, and unified scoring.
 */
export async function analyzeContent(req, res, next) {
  try {
    const { content, language = 'en', inputType = 'message', sender = null } = req.body;

    // 1. Privacy Sanitization: Masks sensitive identifiers (OTP, Cards, Accounts, Aadhaar)
    const { sanitizedText, maskedItemsCount, maskedCategories } = sanitizeSensitiveData(content);

    // 2. Entity Extraction: URLs, Indian Phone numbers, UPI IDs
    const entities = extractEntities(content);

    // 3. Rule-Based Threat Evaluation (Deterministic Baseline)
    const ruleThreatIndicators = evaluateScamRules(content, entities, language);

    // Contextual claims for sender verification
    const hasBankingClaims = ruleThreatIndicators.some((t) => t.category === 'banking_kyc');
    const hasDisconnectionClaims = ruleThreatIndicators.some((t) => t.category === 'utility_disconnection');

    // 4. Sender / Phone Intelligence
    const senderTarget = sender || (entities.phoneNumbers.length === 1 ? entities.phoneNumbers[0] : null);
    const senderIntel = await analyzeSenderIntel(senderTarget, {
      hasBankingClaims,
      hasDisconnectionClaims,
    });

    if (senderIntel?.indicators?.length > 0) {
      for (const ind of senderIntel.indicators) {
        ruleThreatIndicators.push({
          ruleId: ind.id,
          category: ind.category || 'impersonation',
          severity: ind.severity || 'high',
          evidence: ind.description,
        });
      }
    }

    // 4b. URL Intelligence & Threat Scanning for extracted links
    const urlIntel = [];
    if (entities.urls && entities.urls.length > 0) {
      for (const rawUrl of entities.urls) {
        try {
          const formatted = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
          const scan = scanUrl(formatted);
          if (scan) {
            urlIntel.push({
              url: rawUrl,
              hostname: scan.hostname,
              riskScore: scan.riskScore,
              indicators: scan.indicators,
              isSuspicious: scan.riskScore >= 40 || scan.indicators.length > 0,
            });

            for (const ind of scan.indicators) {
              const ruleId = `URL_${ind.id}`;
              const alreadyHas = ruleThreatIndicators.some((t) => t.ruleId === ruleId);
              if (!alreadyHas) {
                ruleThreatIndicators.push({
                  ruleId,
                  category: 'suspicious_url',
                  severity: ind.severity || 'high',
                  evidence:
                    language === 'hi'
                      ? `संदिग्ध लिंक (${rawUrl}): ${ind.description}`
                      : `Suspicious link (${rawUrl}): ${ind.description}`,
                });
              }
            }
          }
        } catch {
          const ruleId = 'URL_MALFORMED_UNVERIFIED';
          if (!ruleThreatIndicators.some((t) => t.ruleId === ruleId)) {
            ruleThreatIndicators.push({
              ruleId,
              category: 'suspicious_url',
              severity: 'high',
              evidence:
                language === 'hi'
                  ? `संदिग्ध असत्यापित लिंक प्रारूप पाया गया: ${rawUrl}`
                  : `Suspicious unverified link format detected: ${rawUrl}`,
            });
          }
        }
      }
    }

    // If sensitive data like OTP was contextually present and requested, add indicator
    if (maskedCategories.includes('otp')) {
      const alreadyHasCreds = ruleThreatIndicators.some((t) => t.category === 'credential_harvesting');
      if (!alreadyHasCreds) {
        ruleThreatIndicators.push({
          ruleId: 'SENSITIVE_OTP_DETECTED',
          category: 'credential_harvesting',
          severity: 'high',
          evidence:
            language === 'hi'
              ? 'संदेश में एक गोपनीय ओटीपी/सत्यापन कोड पाया गया है।'
              : 'Sensitive OTP or verification code pattern detected in the content.',
        });
      }
    }

    // Baseline rule-based metrics
    const { riskScore: ruleScore, riskLevel: ruleLevel } = calculateRiskScore(ruleThreatIndicators, entities);
    const ruleScamType = determineScamType(ruleThreatIndicators);

    let ruleSummary = '';
    if (language === 'hi') {
      if (ruleScamType === 'utility_disconnection') {
        ruleSummary = 'इस संदेश में बिजली/उपयोगिता सेवा विच्छेद की धमकी और असत्यापित नंबर या लिंक पर भुगतान का दबाव पाया गया है।';
      } else if (ruleLevel === 'very_high') {
        ruleSummary = 'इस संदेश में गंभीर धोखाधड़ी और घोटाले के स्पष्ट चेतावनी संकेत पाए गए हैं।';
      } else if (ruleLevel === 'high') {
        ruleSummary = 'इस संदेश में संदिग्ध विशेषताएं और जोखिम संकेतक मौजूद हैं। सावधानी आवश्यक है।';
      } else if (ruleLevel === 'caution') {
        ruleSummary = 'संदेश में कुछ असामान्य तत्व हैं, सत्यापन की सलाह दी जाती है।';
      } else {
        ruleSummary = 'इस संदेश में कोई स्पष्ट दुर्भावनापूर्ण पैटर्न नहीं मिला।';
      }
    } else {
      if (ruleScamType === 'utility_disconnection') {
        ruleSummary = 'This message exhibits fraudulent threats of imminent utility or electricity disconnection demanding immediate payment or callback.';
      } else if (ruleLevel === 'very_high') {
        ruleSummary = 'This message exhibits critical indicators commonly found in verified fraud schemes.';
      } else if (ruleLevel === 'high') {
        ruleSummary = 'This message contains notable suspicious patterns. Independent verification is strongly advised.';
      } else if (ruleLevel === 'caution') {
        ruleSummary = 'Minor suspicious signals detected. Proceed with caution.';
      } else {
        ruleSummary = 'No evident fraudulent patterns were detected in this message.';
      }
    }

    const ruleSafetyAdvice = generateSafetyAdvice(ruleThreatIndicators, entities, language);
    const evidenceExcerpts = extractEvidenceExcerpts(content, ruleThreatIndicators);

    const ruleResults = {
      riskScore: ruleScore,
      riskLevel: ruleLevel,
      scamType: ruleScamType,
      summary: ruleSummary,
      threatIndicators: ruleThreatIndicators,
      safetyAdvice: ruleSafetyAdvice,
    };

    // 5. AI-Powered Contextual Analysis with Gemini (Sanitized content ONLY)
    const { success: aiSuccess, data: aiData, errorReason: aiError } = await analyzeWithGemini(
      sanitizedText,
      language,
      entities
    );

    // 6. Unify Rule and AI Results (Ensures no regression on rule detections and deduplicates indicators)
    const combinedAnalysis = combineEngineResults(
      ruleResults,
      aiSuccess ? aiData : null,
      aiError,
      entities,
      language
    );

    // Attach sender intelligence, URL intelligence, transparent evidence excerpts, and engine version
    combinedAnalysis.senderIntel = senderIntel;
    combinedAnalysis.urlIntel = urlIntel;
    combinedAnalysis.evidenceExcerpts = evidenceExcerpts;
    combinedAnalysis.engineVersion = 'scamsathi_engine_v3';
    combinedAnalysis.analyzedAt = new Date().toISOString();

    // Non-sensitive operational log (never logs content, PII, or raw messages)
    console.log(
      `[Analysis] type=${inputType} lang=${language} engine=${combinedAnalysis.engine} score=${combinedAnalysis.riskScore} level=${combinedAnalysis.riskLevel} indicators=${combinedAnalysis.threatIndicators.length} masked=${maskedItemsCount}`
    );

    // 7. Return standardized response payload
    return res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
      analysis: combinedAnalysis,
    });
  } catch (err) {
    next(err);
  }
}
