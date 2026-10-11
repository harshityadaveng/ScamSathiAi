import React from 'react';
import { X, ArrowRight, Zap, Building, Briefcase, ShieldAlert, Award } from 'lucide-react';

const SAMPLES = [
  {
    id: 'electricity',
    category: { en: 'Electricity Bill Scam', hi: 'बिजली बिल विच्छेद घोटाला' },
    icon: Zap,
    text: {
      en: 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please contact electricity officer at 9876543210 immediately or pay at http://bijli-bill.xyz.',
      hi: 'प्रिय उपभोक्ता, आपकी बिजली आज रात 9:30 बजे काट दी जाएगी क्योंकि आपका पिछले माह का बिल अपडेट नहीं हुआ है। तुरंत बिजली अधिकारी से 9876543210 पर संपर्क करें या http://bijli-bill.xyz पर बिल भरें।'
    },
    risk: { en: 'High Risk (95%)', hi: 'अत्यधिक जोखिम (95%)' }
  },
  {
    id: 'kyc',
    category: { en: 'Banking / PAN KYC Phishing', hi: 'बैंक / पैन केवाईसी फ़िशिंग' },
    icon: Building,
    text: {
      en: 'Dear Customer, your bank account ending in 4102 has been temporarily BLOCKED due to expired PAN KYC. Visit http://sbi-pan-kyc.xyz/verify now to update or your account will be closed.',
      hi: 'प्रिय ग्राहक, आपका बैंक खाता पैन केवाईसी समाप्त होने के कारण अस्थायी रूप से ब्लॉक कर दिया गया है। तुरंत अपडेट करने के लिए http://sbi-pan-kyc.xyz/verify पर जाएं अन्यथा खाता बंद कर दिया जाएगा।'
    },
    risk: { en: 'High Risk (96%)', hi: 'अत्यधिक जोखिम (96%)' }
  },
  {
    id: 'job',
    category: { en: 'Part-Time Telegram Job Fraud', hi: 'पार्ट-टाइम टेलीग्राम जॉब फ्रॉड' },
    icon: Briefcase,
    text: {
      en: 'Congratulations! You are shortlisted for Part-Time Work From Home job. Just like YouTube videos and earn ₹2,500 to ₹8,000 daily. WhatsApp / Telegram HR directly on +91-9812345678.',
      hi: 'बधाई हो! आपको पार्ट-टाइम वर्क फ्रॉम होम नौकरी के लिए चुना गया है। बस यूट्यूब वीडियो लाइक करें और रोजाना ₹2,500 से ₹8,000 कमाएं। तुरंत व्हाट्सएप या टेलीग्राम करें: +91-9812345678।'
    },
    risk: { en: 'High Risk (92%)', hi: 'उच्च जोखिम (92%)' }
  },
  {
    id: 'digital_arrest',
    category: { en: 'Digital Arrest / Police Impersonation', hi: 'डिजिटल अरेस्ट / पुलिस धमकी' },
    icon: ShieldAlert,
    text: {
      en: 'Mumbai Crime Branch Alert: A parcel containing illegal narcotics and fake passports was intercepted in your name. Connect immediately on Skype / WhatsApp video call for judicial verification.',
      hi: 'मुंबई क्राइम ब्रांच अलर्ट: आपके नाम पर अवैध नशीले पदार्थों वाला पार्सल जब्त किया गया है। न्यायिक सत्यापन के लिए तुरंत स्काइप या व्हाट्सएप वीडियो कॉल पर जुड़ें।'
    },
    risk: { en: 'Extreme Risk (98%)', hi: 'गंभीर जोखिम (98%)' }
  },
  {
    id: 'lottery',
    category: { en: 'Lottery & Prize Advance-Fee Scam', hi: 'लॉटरी व इनाम धोखाधड़ी' },
    icon: Award,
    text: {
      en: 'Dear winner, your SIM number has won ₹25,00,000 in KBC All India WhatsApp Lucky Draw. Contact KBC manager Rajiv Sharma on WhatsApp at 9988776655 to claim your prize.',
      hi: 'प्रिय विजेता, आपके सिम नंबर ने केबीसी ऑल इंडिया लकी ड्रॉ में ₹25,00,000 जीते हैं। अपना इनाम पाने के लिए व्हाट्सएप पर केबीसी मैनेजर से 9988776655 पर संपर्क करें।'
    },
    risk: { en: 'High Risk (90%)', hi: 'उच्च जोखिम (90%)' }
  }
];

export default function SampleMessagesModal({ onClose, onSelectSample, language }) {
  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <div>
            <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#171717' }}>
              {language === 'hi' ? 'वास्तविक नमूना संदेश चुनें' : 'Choose a Sample Scam Message'}
            </h3>
            <p style={{ fontSize: '13px', color: '#655E54' }}>
              {language === 'hi' ? 'देखें कि स्कैमसाथी एआई वास्तविक घोटालों का विश्लेषण कैसे करता है' : 'Test ScamSathi AI detection on real-world Indian cyber threats'}
            </p>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#88898D', padding: '6px' }}
            aria-label="Close modal"
          >
            <X size={20} />
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {SAMPLES.map((sample) => {
            const IconComponent = sample.icon;
            const categoryText = sample.category[language] || sample.category.en;
            const sampleText = sample.text[language] || sample.text.en;
            const riskText = sample.risk[language] || sample.risk.en;

            return (
              <div
                key={sample.id}
                onClick={() => onSelectSample(sampleText)}
                style={{
                  background: '#FFF7EC',
                  border: '1px solid #E7DED0',
                  borderRadius: '16px',
                  padding: '16px 18px',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '14px'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = '#B83B00';
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.boxShadow = '0 6px 16px rgba(184, 59, 0, 0.08)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = '#E7DED0';
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '50%',
                    background: '#FFFFFF',
                    border: '1px solid #E7DED0',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#B83B00',
                    flexShrink: 0
                  }}
                >
                  <IconComponent size={20} />
                </div>

                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 800, color: '#171717' }}>
                      {categoryText}
                    </span>
                    <span style={{ fontSize: '11px', fontWeight: 700, color: '#CC191D', background: '#FDE1DE', padding: '2px 8px', borderRadius: '9999px' }}>
                      {riskText}
                    </span>
                  </div>
                  <p style={{ fontSize: '13.5px', color: '#655E54', lineHeight: 1.45 }}>
                    "{sampleText}"
                  </p>
                </div>

                <div style={{ alignSelf: 'center', color: '#B83B00' }}>
                  <ArrowRight size={18} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
