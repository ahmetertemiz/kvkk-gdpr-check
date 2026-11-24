/** Finding categories, in report display order. */
export const CATEGORIES = {
  security: { tr: 'Güvenlik', en: 'Security', icon: '🔐' },
  consent: { tr: 'Rıza', en: 'Consent', icon: '✋' },
  tracking: { tr: 'İzleme & çerezler', en: 'Tracking & cookies', icon: '🍪' },
  transparency: { tr: 'Şeffaflık', en: 'Transparency', icon: '📄' },
  'personal-data': { tr: 'Kişisel veri', en: 'Personal data', icon: '🧾' },
  mobile: { tr: 'Mobil uygulama', en: 'Mobile app', icon: '📱' },
  transfer: { tr: 'Üçüncü taraflar & yurt dışı aktarım', en: 'Third parties & transfers', icon: '🌍' },
  rights: { tr: 'İlgili kişi hakları', en: 'Data subject rights', icon: '🙋' },
  retention: { tr: 'Saklama & imha', en: 'Retention', icon: '⏳' },
  config: { tr: 'Sunucu / framework yapılandırması', en: 'Server / framework config', icon: '⚙️' },
  // Audit engine (principle-based) categories
  special: { tr: 'Özel nitelikli veri', en: 'Special category data', icon: '🩺' },
  minimization: { tr: 'Veri minimizasyonu', en: 'Data minimisation', icon: '✂️' },
  purpose: { tr: 'Amaç sınırlaması', en: 'Purpose limitation', icon: '🎯' },
  'legal-basis': { tr: 'Hukuki sebep', en: 'Legal basis', icon: '⚖️' },
  deletion: { tr: 'Silme kapsamı', en: 'Erasure coverage', icon: '🗑️' },
  dpia: { tr: 'Etki değerlendirmesi (DPIA)', en: 'Impact assessment (DPIA)', icon: '📊' },
};

export const CATEGORY_ORDER = Object.keys(CATEGORIES);
