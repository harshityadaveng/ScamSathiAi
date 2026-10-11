/**
 * Scam Detection Engine
 * Modular rule-based detection for common Indian cyber fraud patterns.
 */

export const RULES = [
  // 1. Urgent Electricity or Utility Disconnection Threat
  {
    ruleId: 'URGENT_UTILITY_DISCONNECTION',
    category: 'utility_disconnection',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasUtilityEn = /\b(?:electricity|bijli|power|power-cut|discom|bses|dhbvn|uppcl|tneb|wbsedcl|bescom|mseb|adani\s*electricity|bill\s*payment|utility)\b/i.test(lower);
      const hasUtilityHi = /(?:बिजली|विद्युत|पावर|मीटर|ऊर्जा|विद्युत\s*विभाग|विद्युत\s*निगम|डिस्कॉम|उपभोक्ता|बिल\s*भुगतान|बिजली\s*बिल|बकाया\s*बिल|लाइट)/i.test(text);
      const hasUtility = hasUtilityEn || hasUtilityHi;

      const hasDisconnectionEn = /\b(?:disconnect|disconnection|cut|cut\s*off|will\s*be\s*disconnected|tonight|night|9:30|8:30|9\.30|8\.30|10:00|10\.00|contact\s*officer|call\s*officer|bill\s*update)\b/i.test(lower);
      const hasDisconnectionHi = /(?:काट\s*दी\s*जाएगी|काट\s*दिया\s*जाएगा|कट\s*जाएगी|कट\s*जाएगा|कनेक्शन\s*कट|कनेक्शन\s*काट|विच्छेद|विच्छेदित|बंद\s*कर|बाधित|आज\s*रात|रात\s*9|रात\s*8|9:30|9\.30|8:30|8\.30|अधिकारी|विद्युत\s*अधिकारी|बिजली\s*अधिकारी|संपर्क\s*करें|कॉल\s*करें|बिल\s*अपडेट|अपडेट\s*नहीं)/i.test(text);
      const hasDisconnection = hasDisconnectionEn || hasDisconnectionHi;

      return hasUtility && hasDisconnection;
    },
    evidence: {
      en: 'Threat of imminent utility or electricity disconnection demanding immediate payment or callback to an unverified number.',
      hi: 'बिजली या उपयोगिता सेवा को तत्काल काटने की धमकी और व्यक्तिगत नंबर पर कॉल करने या लिंक पर भुगतान करने का दबाव।'
    }
  },

  // 2. Banking KYC & Account Suspension Threat
  {
    ruleId: 'BANKING_KYC_THREAT',
    category: 'banking_kyc',
    severity: 'critical',
    check: (text, entities) => {
      const lower = text.toLowerCase();
      const hasBankingEn = /\b(?:bank|sbi|hdfc|icici|pnb|axis|bob|kotak|canara|account|a\/c|netbanking|yono|pan|aadhaar)\b/i.test(lower);
      const hasBankingHi = /(?:बैंक|खाता|अकाउंट|पैन|आधार|केवाईसी|नेटबैंकिंग|योनो|एसबीआई)/i.test(text);
      const hasBanking = hasBankingEn || hasBankingHi;

      const hasSuspensionEn = /\b(?:block|blocked|deactivate|deactivated|suspend|suspended|closed|expire|expired|update\s*kyc|kyc\s*pending|link\s*pan)\b/i.test(lower);
      const hasSuspensionHi = /(?:ब्लॉक|बंद|निलंबित|निष्क्रिय|समाप्त|केवाईसी\s*अपडेट|पैन\s*लिंक|अमान्य|पेंडिंग)/i.test(text);
      const hasSuspension = hasSuspensionEn || hasSuspensionHi;

      const hasActionEn = /\b(?:click|link|verify|update|avoid|login|submit)\b/i.test(lower);
      const hasActionHi = /(?:क्लिक|लिंक|सत्यापित|अपडेट|लॉगिन|दर्ज|जमा|तुरंत)/i.test(text);
      const hasAction = hasActionEn || hasActionHi;

      return (
        (hasBanking && hasSuspension && (hasAction || (entities?.urls && entities.urls.length > 0))) ||
        ((lower.includes('kyc') || /केवाईसी/i.test(text)) && hasSuspension)
      );
    },
    evidence: {
      en: 'False notification claiming your bank account or PAN is blocked/expired, prompting credential submission.',
      hi: 'बैंक खाता या पैन कार्ड ब्लॉक/निष्क्रिय होने का दावा करते हुए विवरण अपडेट करने का दबाव।'
    }
  },

  // 3. Digital Arrest & Law Enforcement Impersonation
  {
    ruleId: 'DIGITAL_ARREST_COERCION',
    category: 'digital_arrest',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasLawEn = /\b(?:cbi|police|customs|crime\s*branch|narcotics|ncb|court|judge|arrest|warrant|fedex|dhl|parcel)\b/i.test(lower);
      const hasLawHi = /(?:सीबीआई|पुलिस|कस्टम्स|क्राइम\s*ब्रांच|नारकोटिक्स|अदालत|कोर्ट|जज|गिरफ्तारी|वारंट|पार्सल)/i.test(text);
      const hasLaw = hasLawEn || hasLawHi;

      const hasCoercionEn = /\b(?:digital\s*arrest|video\s*call|skype|illegal|drugs|contraband|money\s*laundering|compromised|penal\s*code|fir)\b/i.test(lower);
      const hasCoercionHi = /(?:डिजिटल\s*अरेस्ट|वीडियो\s*कॉल|स्काइप|अवैध|ड्रग्स|नशीले|मनी\s*लॉन्ड्रिंग|धारा|एफआईआर|सत्यापन)/i.test(text);
      const hasCoercion = hasCoercionEn || hasCoercionHi;

      return hasLaw && hasCoercion;
    },
    evidence: {
      en: 'Digital Arrest coercion: Impersonating police, customs, or CBI alleging illegal parcels and demanding remote interrogation.',
      hi: 'डिजिटल अरेस्ट धमकी: फर्जी पुलिस, कस्टम्स या सीबीआई अधिकारी बनकर पार्सल में अवैध सामान मिलने का दावा।'
    }
  },

  // 4. Credential & OTP/PIN Harvesting Request
  {
    ruleId: 'CREDENTIAL_HARVESTING_OTP',
    category: 'credential_harvesting',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasSecretEn = /\b(?:otp|one\s*time\s*password|upi\s*pin|atm\s*pin|cvv|password|passcode)\b/i.test(lower);
      const hasSecretHi = /(?:ओटीपी|यूपीआई\s*पिन|पिन|पासवर्ड|पासकोड|सीवीवी|गोपनीय\s*कोड)/i.test(text);
      const hasSecret = hasSecretEn || hasSecretHi;

      const hasRequestEn = /\b(?:share|tell|send|enter|verify|provide|disclose|give|bhejo|batao)\b/i.test(lower);
      const hasRequestHi = /(?:साझा|शेयर|भेजें|भेजो|बताएं|बताओ|दर्ज\s*करें|डालें|दीजिए|दें|सत्यापित)/i.test(text);
      const hasRequest = hasRequestEn || hasRequestHi;

      return hasSecret && hasRequest;
    },
    evidence: {
      en: 'Direct request to disclose sensitive credentials (OTP, UPI PIN, ATM PIN, or passwords).',
      hi: 'ओटीपी, यूपीआई पिन या गोपनीय पासवर्ड साझा करने का सीधा अनुरोध।'
    }
  },

  // 5. Suspicious APK / Malicious App Download
  {
    ruleId: 'SUSPICIOUS_APK_DOWNLOAD',
    category: 'malicious_software',
    severity: 'critical',
    check: (text, entities) => {
      const lower = text.toLowerCase();
      const hasApkFile =
        /\.apk\b/i.test(lower) ||
        /(?:एपीके|\.apk)/i.test(text) ||
        (entities?.urls && entities.urls.some((u) => u.toLowerCase().endsWith('.apk')));
      const hasRemoteApp =
        /\b(?:anydesk|quicksupport|teamviewer|rustdesk|screen\s*share|install\s*app|download\s*app)\b/i.test(lower) ||
        /(?:ऐप\s*डाउनलोड|ऐप\s*इंस्टॉल|एप्लिकेशन\s*इंस्टॉल|स्क्रीन\s*शेयर|रिमोट\s*ऐप)/i.test(text);
      return hasApkFile || hasRemoteApp;
    },
    evidence: {
      en: 'Requests downloading an external .APK file or installing remote screen-sharing software (e.g. AnyDesk/QuickSupport).',
      hi: 'अज्ञात .APK फाइल या स्क्रीन-शेयरिंग रिमोट एक्सेस ऐप (जैसे AnyDesk) डाउनलोड करने का संकेत।'
    }
  },

  // 6. Fake Job Offers & Telegram Task Scams
  {
    ruleId: 'TASK_JOB_ADVANCE_FEE',
    category: 'job_fraud',
    severity: 'high',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasJobEn = /\b(?:part[\s\-]?time|work\s*from\s*home|wfh|job\s*offer|daily\s*income|earn\s*daily|daily\s*earning)\b/i.test(lower);
      const hasJobHi = /(?:पार्ट[\s\-]?टाइम|घर\s*बैठे|वर्क\s*फ्रॉम\s*होम|नौकरी|दैनिक\s*कमाई|रोजाना\s*कमाएं|प्रतिदिन\s*कमाई|रोजगार)/i.test(text);
      const hasJob = hasJobEn || hasJobHi;

      const hasTaskOrPrepaidEn = /\b(?:youtube\s*like|google\s*review|hotel\s*review|telegram|prepaid|task|commission|earn\s*₹|₹\s*\d{3,5})\b/i.test(lower);
      const hasTaskOrPrepaidHi = /(?:यूट्यूब\s*लाइक|रिव्यू|टेलीग्राम|प्रीपेड|टास्क|कमीशन|लाइक\s*करें|₹\s*\d{3,5})/i.test(text);
      const hasTaskOrPrepaid = hasTaskOrPrepaidEn || hasTaskOrPrepaidHi;

      return hasJob && hasTaskOrPrepaid;
    },
    evidence: {
      en: 'Unrealistic income promise for minimal tasks (liking videos, writing reviews) directing to Telegram or WhatsApp.',
      hi: 'यूट्यूब लाइक या रिव्यू जैसे साधारण कार्यों के लिए अवास्तविक दैनिक कमाई का वादा।'
    }
  },

  // 7. Lottery, Prize, and Reward Advance-Fee Scam
  {
    ruleId: 'LOTTERY_PRIZE_ADVANCE_FEE',
    category: 'lottery_reward',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasRewardEn = /\b(?:lottery|lucky\s*draw|kbc|won|winner|cash\s*prize|gift\s*card|reward|congratulations)\b/i.test(lower);
      const hasRewardHi = /(?:लॉटरी|लकी\s*ड्रॉ|केबीसी|विजेता|जीते|जीता|जीत|इनाम|नकद\s*पुरस्कार|बधाई)/i.test(text);
      const hasReward = hasRewardEn || hasRewardHi;

      const hasFeeOrScaleEn = /\b(?:lakh|crore|deposit|processing\s*fee|registration\s*fee|tax|claim\s*prize|claim\s*amount)\b/i.test(lower);
      const hasFeeOrScaleHi = /(?:लाख|करोड़|रुपये|रुपए|जमा|प्रोसेसिंग\s*फीस|पंजीकरण\s*शुल्क|रजिस्ट्रेशन\s*फीस|टैक्स|दावा\s*करें|क्लेम)/i.test(text);
      const hasFeeOrScale = hasFeeOrScaleEn || hasFeeOrScaleHi;

      return hasReward && hasFeeOrScale;
    },
    evidence: {
      en: 'Claims you won a lottery or lucky draw requiring an advance registration fee or tax deposit.',
      hi: 'लॉटरी या केबीसी लकी ड्रा जीतने का झूठा दावा और इनाम पाने के लिए अग्रिम शुल्क की मांग।'
    }
  },

  // 8. Suspicious Instant Loan Offer & Processing Advance
  {
    ruleId: 'SUSPICIOUS_LOAN_OFFER',
    category: 'loan_fraud',
    severity: 'high',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasLoanEn = /\b(?:instant\s*loan|pre[\s\-]?approved\s*loan|personal\s*loan|fast\s*loan)\b/i.test(lower);
      const hasLoanHi = /(?:तुरंत\s*लोन|पर्सनल\s*लोन|तत्काल\s*ऋण|आसान\s*लोन|लोन\s*ऑफर)/i.test(text);
      const hasLoan = hasLoanEn || hasLoanHi;

      const hasNoCheckEn = /\b(?:without\s*cibil|no\s*documents|0%\s*interest|instant\s*disbursal|processing\s*charges?|advance\s*fee)\b/i.test(lower);
      const hasNoCheckHi = /(?:बिना\s*सिबिल|बिना\s*दस्तावेज|0%\s*ब्याज|तुरंत\s*अप्रूवल|प्रोसेसिंग\s*चार्ज|अग्रिम\s*शुल्क)/i.test(text);
      const hasNoCheck = hasNoCheckEn || hasNoCheckHi;

      return hasLoan && hasNoCheck;
    },
    evidence: {
      en: 'Unregulated instant loan offer claiming zero credit checks while demanding upfront processing fees.',
      hi: 'बिना सिबिल स्कोर या बिना दस्तावेज के तत्काल लोन का वादा और अग्रिम प्रोसेसिंग फीस की मांग।'
    }
  },

  // 9. Institutional Impersonation
  {
    ruleId: 'GOVT_BANK_IMPERSONATION',
    category: 'impersonation',
    severity: 'medium',
    check: (text, entities) => {
      const lower = text.toLowerCase();
      const claimsOrgEn = /\b(?:reserve\s*bank\s*of\s*india|rbi|income\s*tax|trai|dot|customs|sbi|mha|police)\b/i.test(lower);
      const claimsOrgHi = /(?:भारतीय\s*रिजर्व\s*बैंक|आरबीआई|आयकर|ट्राई|सीमा\s*शुल्क|पुलिस|गृह\s*मंत्रालय|एसबीआई)/i.test(text);
      const claimsOrg = claimsOrgEn || claimsOrgHi;
      const hasUnverifiedContact = (entities?.phoneNumbers && entities.phoneNumbers.length > 0) ||
        (entities?.upiIds && entities.upiIds.length > 0) ||
        (entities?.urls && entities.urls.length > 0);
      return claimsOrg && hasUnverifiedContact;
    },
    evidence: {
      en: 'References government authorities or financial institutions alongside unofficial contact or payment channels.',
      hi: 'सरकारी विभाग या बैंक का नाम लेते हुए अनधिकृत संपर्क या भुगतान चैनलों का उपयोग।'
    }
  },

  // 10. Artificial Urgency & Coercive Pressure
  {
    ruleId: 'EXTREME_URGENCY_PRESSURE',
    category: 'urgency_coercion',
    severity: 'medium',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const urgencyMatchEn = /\b(?:immediately|urgent|within\s*\d+\s*(?:hours?|minutes?|mins?)|today\s*itself|last\s*chance|before\s*(?:midnight|tonight)|action\s*required)\b/i.test(lower);
      const urgencyMatchHi = /(?:तुरंत|तत्काल|जल्द|आज\s*ही|आखिरी\s*मौका|अंतिम\s*अवसर|आज\s*रात\s*से\s*पहले|अनिवार्य)/i.test(text);
      const urgencyMatch = urgencyMatchEn || urgencyMatchHi;

      const pressureMatchEn = /\b(?:legal\s*action|penalty|court|fine|lawsuit|permanent\s*loss|confiscate)\b/i.test(lower);
      const pressureMatchHi = /(?:कानूनी\s*कार्रवाई|जुर्माना|पेनाल्टी|अदालत|कार्रवाई\s*की\s*जाएगी|जब्त)/i.test(text);
      const pressureMatch = pressureMatchEn || pressureMatchHi;

      return urgencyMatch && pressureMatch;
    },
    evidence: {
      en: 'Psychological urgency tactic creating fear of immediate financial penalty or legal action.',
      hi: 'त्वरित जुर्माने या कानूनी कार्रवाई का भय दिखाकर जल्दबाजी में कदम उठाने का मानसिक दबाव।'
    }
  },

  // 11. Fake Courier Delivery & Customs Fee Scam
  {
    ruleId: 'COURIER_CUSTOMS_FEE_SCAM',
    category: 'courier_customs_fraud',
    severity: 'high',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasCourierEn = /\b(?:fedex|dhl|indiapost|india\s*post|speedpost|blue\s*dart|delhivery|parcel|package|shipment|delivery|order)\b/i.test(lower);
      const hasCourierHi = /(?:इंडिया\s*पोस्ट|भारतीय\s*डाक|स्पीड\s*पोस्ट|पार्सल|पैकेज|शिपमेंट|डिलीवरी|कूरियर)/i.test(text);
      const hasCourier = hasCourierEn || hasCourierHi;

      const hasFeeOrAddressEn = /\b(?:customs|duty|tax|redelivery|reschedule|delivery\s*fee|update\s*address|wrong\s*address|pending\s*charges?|₹\s*\d{1,4}|rs\.?\s*\d{1,4})\b/i.test(lower);
      const hasFeeOrAddressHi = /(?:कस्टम|सीमा\s*शुल्क|री-डिलीवरी|डिलीवरी\s*शुल्क|पता\s*अपडेट|गलत\s*पता|बकाया\s*शुल्क)/i.test(text);
      const hasFeeOrAddress = hasFeeOrAddressEn || hasFeeOrAddressHi;

      const hasActionEn = /\b(?:click|link|pay|visit|update|track)\b/i.test(lower);
      const hasActionHi = /(?:क्लिक|लिंक|भुगतान|अपडेट|ट्रैक)/i.test(text);
      const hasAction = hasActionEn || hasActionHi;

      return (hasCourier && hasFeeOrAddress) || (hasCourier && hasAction && /\b(?:failed|incomplete|undelivered|held)\b/i.test(lower));
    },
    evidence: {
      en: 'Fake parcel delivery or customs charges notification demanding immediate payment or address updates to release shipment.',
      hi: 'पार्सल या डाक डिलीवरी रोकने का दावा करते हुए सीमा शुल्क या पुनः डिलीवरी शुल्क मांगने का झांसा।'
    }
  },

  // 12. Fraudulent UPI Collect Request ("Enter PIN to receive money")
  {
    ruleId: 'UPI_COLLECT_PIN_SCAM',
    category: 'payment_collect_fraud',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasUpiEn = /\b(?:upi|gpay|phonepe|paytm|bhim|qr\s*code|collect\s*request|request\s*money)\b/i.test(lower);
      const hasUpiHi = /(?:यूपीआई|गूगल\s*पे|फोनपे|पेटीएम|भीम|क्यूआर\s*कोड|कलेक्ट\s*रिक्वेस्ट)/i.test(text);
      const hasUpi = hasUpiEn || hasUpiHi;

      const hasPinTrapEn = /\b(?:enter\s*pin|enter\s*upi\s*pin|pin\s*daale|paise\s*(?:aayenge|milenge)|receive\s*money|credit\s*amount|refund|cashback)\b/i.test(lower);
      const hasPinTrapHi = /(?:पिन\s*दर्ज\s*करें|पिन\s*डालें|यूपीआई\s*पिन\s*डालें|पैसे\s*प्राप्त\s*करें|रिफंड|कैशबैक|खाते\s*में\s*आएंगे|पैसे\s*मिलेंगे)/i.test(text);
      const hasPinTrap = hasPinTrapEn || hasPinTrapHi;

      return hasUpi && hasPinTrap;
    },
    evidence: {
      en: 'Deceptive claim that entering a UPI PIN will receive money or credit a refund (UPI PIN is ONLY required for debiting money).',
      hi: 'पैसे प्राप्त करने के लिए यूपीआई पिन डालने का झूठा दावा (यूपीआई पिन केवल पैसे कटने पर ही डाला जाता है)।'
    }
  },

  // 13. High-Yield Investment, Crypto & Guaranteed Returns Scam
  {
    ruleId: 'HIGH_YIELD_INVESTMENT_SCAM',
    category: 'investment_fraud',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasInvestmentEn = /\b(?:invest|investment|crypto|bitcoin|trading|forex|stock|ipo|fund|deposit)\b/i.test(lower);
      const hasInvestmentHi = /(?:निवेश|क्रिप्टो|ट्रेडिंग|शेयर|फंड|जमा)/i.test(text);
      const hasInvestment = hasInvestmentEn || hasInvestmentHi;

      const hasUnrealisticReturnEn = /\b(?:guaranteed\s*returns?|daily\s*returns?|double\s*money|100%\s*profit|vip\s*signals?|assured\s*income|zero\s*risk|10x|20x|passive\s*income)\b/i.test(lower);
      const hasUnrealisticReturnHi = /(?:गारंटीड\s*रिटर्न|दैनिक\s*मुनाफा|पैसे\s*दोगुना|100%\s*मुनाफा|निश्चित\s*आय|बिना\s*जोखिम|गारंटी)/i.test(text);
      const hasUnrealisticReturn = hasUnrealisticReturnEn || hasUnrealisticReturnHi;

      return hasInvestment && hasUnrealisticReturn;
    },
    evidence: {
      en: 'Fraudulent high-yield investment scheme promising guaranteed, zero-risk returns or trading profits.',
      hi: 'बिना जोखिम के गारंटीकृत भारी मुनाफे या दोगुने रिटर्न का वादा करने वाला फर्जी निवेश प्रलोभन।'
    }
  },

  // 14. Suspicious Unverified or Shortened URL in Message
  {
    ruleId: 'SUSPICIOUS_UNVERIFIED_URL',
    category: 'suspicious_url',
    severity: 'high',
    check: (text, entities) => {
      if (!entities?.urls || entities.urls.length === 0) return false;
      const lower = text.toLowerCase();
      const hasSuspiciousUrlPattern = entities.urls.some((u) => {
        const uLower = u.toLowerCase();
        return (
          /\.(?:xyz|top|online|site|live|tk|ml|ga|cf|gq|club|vip|icu|shop|store|link|click|buzz|rest|fit|work|me|pw|ws|bid|cam|quest)(?:\/|$)/i.test(uLower) ||
          /(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|ow\.ly|cutt\.ly|rb\.gy|shorturl\.at|t\.ly|v\.gd)(?:\/|$)/i.test(uLower) ||
          /^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/i.test(uLower) ||
          /(?:bill|bijli|uppcl|power|discom|pay|verify|update|kyc|secure|bank|login|yono|sbi|claim|reward)/i.test(uLower)
        );
      });
      const hasLureContext =
        /(?:electricity|bijli|power|विद्युत|काट|bank|sbi|pan|kyc|बैंक|खाता|lottery|लॉटरी|click|link|update|pay|तुरंत|अपडेट|क्लिक|लिंक)/i.test(lower) ||
        /(?:बिजली|विद्युत|काट\s*दी|बैंक|खाता|केवाईसी|पैन|क्लिक|लिंक)/i.test(text);
      return hasSuspiciousUrlPattern || (entities.urls.length > 0 && hasLureContext);
    },
    evidence: {
      en: 'Suspicious or unverified external link detected in message designed to redirect users to an unofficial portal.',
      hi: 'संदेश में संदिग्ध या असत्यापित लिंक पाया गया है जो अनधिकृत वेबसाइट या फ़िशिंग पेज पर ले जाने के लिए बनाया गया है।'
    }
  }
];

/**
 * Executes all rules against the input text and extracted entities.
 * @param {string} text - Raw input text
 * @param {{ urls: string[], phoneNumbers: string[], upiIds: string[] }} entities
 * @param {'en' | 'hi'} language
 * @returns {Array<{ ruleId: string, category: string, severity: string, evidence: string }>}
 */
export function evaluateScamRules(text, entities, language = 'en') {
  if (!text || typeof text !== 'string') return [];

  const matchedRules = [];

  for (const rule of RULES) {
    try {
      if (rule.check(text, entities)) {
        matchedRules.push({
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          evidence: rule.evidence[language] || rule.evidence.en,
        });
      }
    } catch (err) {
      console.error(`Rule evaluation error [${rule.ruleId}]:`, err.message);
    }
  }

  return matchedRules;
}

/**
 * Determines primary scam type from triggered rules.
 */
export function determineScamType(matchedRules) {
  if (!matchedRules || matchedRules.length === 0) {
    return 'none_detected';
  }

  // Prioritize critical rules first, then high
  const priorityOrder = ['critical', 'high', 'medium', 'low'];
  for (const severity of priorityOrder) {
    const found = matchedRules.find((r) => r.severity === severity);
    if (found) return found.category;
  }

  return matchedRules[0].category;
}

/**
 * Generates actionable safety advice based on matched threat rules and entities.
 * @param {Array<{ ruleId: string, category: string }>} matchedRules
 * @param {{ urls: string[], phoneNumbers: string[], upiIds: string[] }} entities
 * @param {'en' | 'hi'} language
 * @returns {string[]}
 */
export function generateSafetyAdvice(matchedRules, entities, language = 'en') {
  const advice = new Set();
  const ruleCategories = new Set(matchedRules.map((r) => r.category));
  const isHi = language === 'hi';

  // 1. OTP / Credential Harvesting
  if (ruleCategories.has('credential_harvesting')) {
    advice.add(
      isHi
        ? 'बैंक या कोई भी आधिकारिक संस्था कभी भी फोन या एसएमएस पर आपका ओटीपी, यूपीआई पिन या पासवर्ड नहीं मांगती। किसी से साझा न करें।'
        : 'Never share OTPs, PINs, CVVs, or passwords with anyone. Banks and official agencies will never ask for them.'
    );
  }

  // 2. Suspicious URLs / Links
  if ((entities?.urls && entities.urls.length > 0) || ruleCategories.has('suspicious_url') || ruleCategories.has('malicious_software') || ruleCategories.has('banking_kyc')) {
    advice.add(
      isHi
        ? 'संदिग्ध संदेश में दिए गए लिंक पर क्लिक न करें। बिजली बिल, बैंक या सरकारी सेवाओं के लिए केवल उनकी आधिकारिक वेबसाइट या ऐप का ही उपयोग करें।'
        : 'Do not click links supplied in unsolicited messages. Always verify domains independently through official portals.'
    );
  }

  // 3. Utility / Disconnection
  if (ruleCategories.has('utility_disconnection')) {
    advice.add(
      isHi
        ? 'बिजली या उपयोगिता बिल की स्थिति केवल आधिकारिक डिस्कॉम ऐप या आधिकारिक वेबसाइट पर ही जांचें। व्यक्तिगत नंबर पर कॉल न करें।'
        : 'Verify utility payment status exclusively through the official DISCOM portal or electricity bill app, not personal phone numbers.'
    );
  }

  // 4. Digital Arrest / Police Impersonation
  if (ruleCategories.has('digital_arrest')) {
    advice.add(
      isHi
        ? 'भारतीय कानून में "डिजिटल अरेस्ट" का कोई प्रावधान नहीं है। पुलिस या सीबीआई कभी भी व्हाट्सएप/स्काइप वीडियो कॉल पर गिरफ्तारी नहीं करती।'
        : 'Indian law enforcement does not conduct arrests or judicial verification via Skype or WhatsApp video calls.'
    );
  }

  // 5. Job & Task Scams
  if (ruleCategories.has('job_fraud')) {
    advice.add(
      isHi
        ? 'साधारण कार्यों के लिए पैसे कमाने का झांसा देने वाले टेलीग्राम या व्हाट्सएप ग्रुपों से दूर रहें। कभी भी "प्रीपेड टास्क" के लिए पैसे न भेजें।'
        : 'Avoid Telegram channels promising daily income for social media tasks. Legitimate jobs never require advance deposits.'
    );
  }

  // 6. Lottery & Advance-Fee
  if (ruleCategories.has('lottery_reward')) {
    advice.add(
      isHi
        ? 'जिस लॉटरी में आपने भाग नहीं लिया, वह आप कभी नहीं जीत सकते। इनाम पाने के लिए कभी कोई शुल्क या टैक्स न दें।'
        : 'You cannot win a contest or lottery you never entered. Real organizations do not demand processing fees to release prizes.'
    );
  }

  // 7. Courier & Customs Scams
  if (ruleCategories.has('courier_customs_fraud')) {
    advice.add(
      isHi
        ? 'कूरियर या डाक विभाग कभी भी एसएमएस पर पार्सल छुड़ाने के लिए ऑनलाइन पैसे नहीं मांगता। आधिकारिक ट्रैकिंग नंबर से सीधे वेबसाइट पर स्थिति जांचें।'
        : 'India Post, FedEx, or customs officials never demand payment via unofficial SMS links to release parcels. Verify tracking on official websites only.'
    );
  }

  // 8. UPI Collect Request & PIN Trap
  if (ruleCategories.has('payment_collect_fraud')) {
    advice.add(
      isHi
        ? 'ध्यान रखें: पैसे प्राप्त करने के लिए कभी भी UPI PIN डालने की आवश्यकता नहीं होती। UPI PIN केवल पैसे भेजने (कटने) पर ही डाला जाता है।'
        : 'CRITICAL: You never need to enter your UPI PIN to receive money or refunds. Entering a PIN will instantly debit your account.'
    );
  }

  // 9. Investment & Guaranteed Returns Fraud
  if (ruleCategories.has('investment_fraud')) {
    advice.add(
      isHi
        ? 'असामान्य रूप से उच्च या गारंटीकृत रिटर्न का वादा करने वाले किसी भी टेलीग्राम या अज्ञात ट्रेडिंग चैनल में पैसे निवेश न करें। यह पोंजी/धोखाधड़ी है।'
        : 'Never invest through WhatsApp/Telegram trading channels promising guaranteed or double returns. Unregulated schemes are high-risk financial fraud.'
    );
  }

  // 10. General / Baseline Advice if high risk detected
  if (matchedRules.length > 0) {
    advice.add(
      isHi
        ? 'यदि आपको वित्तीय नुकसान हुआ है या संदेह है, तो तुरंत राष्ट्रीय साइबर हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत दर्ज करें।'
        : 'If you suspect financial cyber fraud, report immediately to the National Cyber Helpline 1930 or visit https://www.cybercrime.gov.in/.'
    );
  } else {
    // Clean/Benign message
    advice.add(
      isHi
        ? 'इस संदेश में कोई स्पष्ट घोटाला संकेत नहीं मिले। फिर भी अज्ञात संपर्कों से आने वाले किसी भी वित्तीय अनुरोध पर सतर्क रहें।'
        : 'No obvious fraudulent indicators were detected. Continue exercising caution when dealing with unverified senders.'
    );
  }

  return Array.from(advice);
}

/**
 * Extracts verbatim evidence excerpts from the submitted text for matched threat rules.
 * Extracts context around the triggering keywords (up to 80 chars) to provide transparent proof.
 *
 * @param {string} text - Raw input text
 * @param {Array<{ ruleId: string, category: string }>} matchedRules
 * @returns {Array<{ ruleId: string, category: string, excerpt: string }>}
 */
export function extractEvidenceExcerpts(text, matchedRules = []) {
  if (!text || typeof text !== 'string' || matchedRules.length === 0) {
    return [];
  }

  const excerpts = [];
  const seenExcerpts = new Set();

  const patternKeywords = {
    URGENT_UTILITY_DISCONNECTION: /(?:electricity|bijli|power-cut|disconnection|cut off|tonight|contact officer|बिजली|विद्युत|काट दी|कट जाएगी|अधिकारी|बिल)[^.\n\u0964\u0965]{0,50}/i,
    BANKING_KYC_THREAT: /(?:bank|account|a\/c|pan|aadhaar|blocked|deactivated|suspended|update kyc|kyc pending|बैंक|खाता|पैन|आधार|केवाईसी|ब्लॉक)[^.\n\u0964\u0965]{0,50}/i,
    DIGITAL_ARREST_COERCION: /(?:cbi|police|customs|digital arrest|video call|illegal parcel|narcotics|सीबीआई|पुलिस|कस्टम्स|डिजिटल अरेस्ट|पार्सल)[^.\n\u0964\u0965]{0,50}/i,
    CREDENTIAL_HARVESTING_OTP: /(?:otp|password|upi pin|atm pin|cvv|share|enter|send|provide|ओटीपी|पिन|पासवर्ड|साझा|भेजें)[^.\n\u0964\u0965]{0,50}/i,
    SUSPICIOUS_APK_DOWNLOAD: /(?:\.apk|anydesk|quicksupport|teamviewer|screen share|install app|ऐप डाउनलोड|रिमोट)[^.\n\u0964\u0965]{0,50}/i,
    TASK_JOB_ADVANCE_FEE: /(?:part[\s\-]?time|work from home|youtube like|telegram|prepaid task|daily income|पार्ट टाइम|घर बैठे|टेलीग्राम)[^.\n\u0964\u0965]{0,50}/i,
    LOTTERY_PRIZE_ADVANCE_FEE: /(?:lottery|lucky draw|kbc|winner|cash prize|processing fee|tax deposit|लॉटरी|केबीसी|इनाम|विजेता)[^.\n\u0964\u0965]{0,50}/i,
    SUSPICIOUS_LOAN_OFFER: /(?:instant loan|without cibil|no documents|0% interest|processing fee|तुरंत लोन|बिना सिबिल)[^.\n\u0964\u0965]{0,50}/i,
    COURIER_CUSTOMS_FEE_SCAM: /(?:fedex|dhl|indiapost|speedpost|parcel|delivery fee|customs duty|reschedule|पार्सल|कस्टम|कूरियर)[^.\n\u0964\u0965]{0,50}/i,
    UPI_COLLECT_PIN_SCAM: /(?:upi|collect request|enter pin|receive money|refund|cashback|पिन दर्ज|पैसे मिलेंगे|यूपीआई पिन)[^.\n\u0964\u0965]{0,50}/i,
    HIGH_YIELD_INVESTMENT_SCAM: /(?:guaranteed returns?|double money|crypto trading|100% profit|vip signal|गारंटीड रिटर्न|पैसे दोगुना)[^.\n\u0964\u0965]{0,50}/i,
    EXTREME_URGENCY_PRESSURE: /(?:immediately|urgent|within \d+ hours?|today itself|last chance|legal action|तुरंत|तत्काल|कानूनी कार्रवाई)[^.\n\u0964\u0965]{0,50}/i,
    GOVT_BANK_IMPERSONATION: /(?:rbi|income tax|trai|customs|police|आरबीआई|आयकर|पुलिस)[^.\n\u0964\u0965]{0,50}/i,
    SUSPICIOUS_UNVERIFIED_URL: /(?:https?:\/\/[^\s\u0964\u0965]+|www\.[^\s\u0964\u0965]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s\u0964\u0965]*)?)/i,
  };

  for (const rule of matchedRules) {
    const regex = patternKeywords[rule.ruleId];
    if (regex) {
      const match = regex.exec(text);
      if (match) {
        const snippet = match[0].trim();
        if (snippet && !seenExcerpts.has(snippet)) {
          seenExcerpts.add(snippet);
          excerpts.push({
            ruleId: rule.ruleId,
            category: rule.category,
            excerpt: `"...${snippet}..."`,
          });
        }
      }
    }
  }

  return excerpts;
}
