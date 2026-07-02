<?php
require __DIR__ . '/security.php';
bootstrapSecureSession();
sendSecurityHeaders();
session_start();

$auth = $_SESSION['auth'] ?? null;

$theme = strtolower($_GET['theme'] ?? ($_COOKIE['theme'] ?? 'dark'));
if (!in_array($theme, ['dark', 'light'], true)) {
    $theme = 'dark';
}
setcookie('theme', $theme, time() + 60 * 60 * 24 * 365, '/', '', false, true);

$availableLanguages = ['ku' => 'Kurdish', 'en' => 'English', 'ar' => 'Arabic'];
$defaultLanguage = 'ku';
$lang = strtolower($_GET['lang'] ?? $_SESSION['lang'] ?? $defaultLanguage);
if (!isset($availableLanguages[$lang])) {
    $lang = $defaultLanguage;
}
$_SESSION['lang'] = $lang;

$defaultPhone = '07701992299';
$defaultEmail = 'reyonicapp@gmail.com';

function e($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

function normalizePhoneForWhatsApp($phone) {
    $phone = preg_replace('/[^0-9+]/', '', (string) $phone);
    return strpos($phone, '+') === 0 ? ltrim($phone, '+') : $phone;
}

function whatsappLink($phone, $text) {
    $phone = normalizePhoneForWhatsApp($phone);
    return $phone === '' ? '#' : 'https://wa.me/' . rawurlencode($phone) . '?text=' . rawurlencode($text);
}

$T = [
    'en' => [
        'site_title' => 'About — Reyonic',
        'site_subtitle' => 'Local marketplace',
        'nav_home' => 'Home',
        'nav_products' => 'Products',
        'nav_about' => 'About',
        'nav_contact' => 'Contact',
        'login' => 'Login',
        'my_shop' => 'My shop',
        'admin' => 'Admin',
        'logout' => 'Logout',
        'language' => 'Language',
        'light' => 'Light',
        'dark' => 'Dark',
        'theme_toggle' => 'Toggle theme',
        'about_badge' => 'About Reyonic',
        'about_title' => 'A local marketplace built for real neighborhood businesses',
        'about_lead' => 'Reyonic gives local sellers a simple, modern storefront and gives shoppers one place to discover them — no middlemen, no complicated setup.',
        'mission_title' => 'Our mission',
        'mission_text' => 'We believe every local shop deserves a clean online presence. Reyonic helps sellers list products, track sales, and stay in touch with customers, while shoppers get a fast, honest way to browse nearby businesses.',
        'how_title' => 'How Reyonic works',
        'for_customers' => 'For customers',
        'customer_step_1_title' => 'Browse freely',
        'customer_step_1_text' => 'Explore shops and products without creating an account.',
        'customer_step_2_title' => 'Find what you need',
        'customer_step_2_text' => 'Search by name, category, or location to find the right seller.',
        'customer_step_3_title' => 'Connect directly',
        'customer_step_3_text' => 'Reach sellers instantly by WhatsApp, call, or email.',
        'for_sellers' => 'For sellers',
        'seller_step_1_title' => 'Set up your shop',
        'seller_step_1_text' => 'Add your business profile, logo, and contact details in minutes.',
        'seller_step_2_title' => 'List your products',
        'seller_step_2_text' => 'Manage products, prices, stock status, and categories yourself.',
        'seller_step_3_title' => 'Track your growth',
        'seller_step_3_text' => 'See visitor analytics and sales reports right from your dashboard.',
        'contact_title' => 'Get in touch',
        'contact_text' => 'Questions, feedback, or want to list your shop on Reyonic? We would love to hear from you.',
        'contact_whatsapp' => 'WhatsApp',
        'contact_call' => 'Call',
        'contact_email' => 'Email',
        'back_home' => 'Back to marketplace',
        'footer' => 'Reyonic — Local marketplace prototype',
    ],
    'ku' => [
        'site_title' => 'دەربارە — ڕێۆنیک',
        'site_subtitle' => 'بازاڕی ناوخۆیی',
        'nav_home' => 'سەرەکی',
        'nav_products' => 'بەرهەمەکان',
        'nav_about' => 'دەربارە',
        'nav_contact' => 'پەیوەندی',
        'login' => 'چوونەژوورەوە',
        'my_shop' => 'دوکانەکەم',
        'admin' => 'ئەدمین',
        'logout' => 'دەرچوون',
        'language' => 'زمان',
        'light' => 'ڕووناک',
        'dark' => 'تاریک',
        'theme_toggle' => 'گۆڕینی ڕووکار',
        'about_badge' => 'دەربارەی ڕێۆنیک',
        'about_title' => 'بازاڕێکی ناوخۆیی بۆ بازرگانە ڕاستەقینەکانی گەڕەک',
        'about_lead' => 'ڕێۆنیک دوکانێکی ئۆنلاینی سادە و مۆدێرن دەداتە فرۆشیارە ناوخۆییەکان، و شوێنێک بۆ کڕیاران دادەنێت تاکو هەموو دوکانەکان بدۆزنەوە — بەبێ ناوبژیوان و بەبێ ئاماده‌کاریی ئاڵۆز.',
        'mission_title' => 'ئامانجمان',
        'mission_text' => 'باوەڕمان وایە هەموو دوکانێکی ناوخۆیی شایانی بوونی ئۆنلاینێکی جوانە. ڕێۆنیک یارمەتی فرۆشیاران دەدات بۆ زیادکردنی بەرهەم، چاودێریکردنی فرۆشتن، و پەیوەندیگرتن لەگەڵ کڕیاران، لەکاتێکدا کڕیاران ڕێگایەکی خێرا و ڕاستگۆیانە بۆ گەڕان بەناو بازرگانییە نزیکەکان بەدەستدەهێنن.',
        'how_title' => 'ڕێۆنیک چۆن کاردەکات',
        'for_customers' => 'بۆ کڕیاران',
        'customer_step_1_title' => 'بەئازادی بگەڕێ',
        'customer_step_1_text' => 'دوکان و بەرهەمەکان بگەڕێ بەبێ دروستکردنی هەژمار.',
        'customer_step_2_title' => 'ئەوەی پێویستە بدۆزەرەوە',
        'customer_step_2_text' => 'بەپێی ناو، جۆر، یان شوێن بگەڕێ بۆ دۆزینەوەی فرۆشیاری گونجاو.',
        'customer_step_3_title' => 'ڕاستەوخۆ پەیوەندی بکە',
        'customer_step_3_text' => 'بە خێرایی بگە فرۆشیاران لە ڕێگەی واتساپ، پەیوەندی، یان ئیمەیل.',
        'for_sellers' => 'بۆ فرۆشیاران',
        'seller_step_1_title' => 'دوکانەکەت ئاماده بکە',
        'seller_step_1_text' => 'پڕۆفایلی بازرگانی، لۆگۆ، و زانیاری پەیوەندیت لە چەند خولەکێکدا زیاد بکە.',
        'seller_step_2_title' => 'بەرهەمەکانت زیاد بکە',
        'seller_step_2_text' => 'بەرهەم، نرخ، دۆخی بازاڕ، و جۆرەکان خۆت بەڕێوەببە.',
        'seller_step_3_title' => 'گەشەکردنت بەدواداچوون بکە',
        'seller_step_3_text' => 'ئامارەکانی سەردانکردن و ڕاپۆرتی فرۆشتن لە داشبۆردی خۆتەوە ببینە.',
        'contact_title' => 'پەیوەندیمان پێوە بکە',
        'contact_text' => 'پرسیار، بۆچوون، یان دەتەوێت دوکانەکەت لەسەر ڕێۆنیک تۆمار بکەیت؟ خۆشحاڵ دەبین بیستنی دەنگت.',
        'contact_whatsapp' => 'واتساپ',
        'contact_call' => 'پەیوەندی',
        'contact_email' => 'ئیمەیل',
        'back_home' => 'گەڕانەوە بۆ بازاڕ',
        'footer' => 'ڕێۆنیک — پڕۆتۆتایپی بازاڕی ناوخۆیی',
    ],
    'ar' => [
        'site_title' => 'حول — ريونيك',
        'site_subtitle' => 'سوق محلي',
        'nav_home' => 'الرئيسية',
        'nav_products' => 'المنتجات',
        'nav_about' => 'حول',
        'nav_contact' => 'تواصل',
        'login' => 'تسجيل الدخول',
        'my_shop' => 'متجري',
        'admin' => 'المشرف',
        'logout' => 'تسجيل الخروج',
        'language' => 'اللغة',
        'light' => 'فاتح',
        'dark' => 'داكن',
        'theme_toggle' => 'تبديل المظهر',
        'about_badge' => 'حول ريونيك',
        'about_title' => 'سوق محلي مصمم لبائعي الأحياء الحقيقيين',
        'about_lead' => 'يمنح ريونيك البائعين المحليين متجرًا إلكترونيًا بسيطًا وعصريًا، ويمنح المتسوقين مكانًا واحدًا لاكتشافهم — بلا وسطاء وبلا إعداد معقد.',
        'mission_title' => 'مهمتنا',
        'mission_text' => 'نؤمن بأن كل متجر محلي يستحق حضورًا إلكترونيًا أنيقًا. يساعد ريونيك البائعين على إدراج المنتجات ومتابعة المبيعات والتواصل مع العملاء، بينما يحصل المتسوقون على طريقة سريعة وصادقة لتصفح المتاجر القريبة.',
        'how_title' => 'كيف يعمل ريونيك',
        'for_customers' => 'للعملاء',
        'customer_step_1_title' => 'تصفح بحرية',
        'customer_step_1_text' => 'استكشف المتاجر والمنتجات دون إنشاء حساب.',
        'customer_step_2_title' => 'اعثر على ما تحتاجه',
        'customer_step_2_text' => 'ابحث بالاسم أو الفئة أو الموقع للعثور على البائع المناسب.',
        'customer_step_3_title' => 'تواصل مباشرة',
        'customer_step_3_text' => 'تواصل مع البائعين فورًا عبر واتساب أو الاتصال أو البريد الإلكتروني.',
        'for_sellers' => 'للبائعين',
        'seller_step_1_title' => 'أنشئ متجرك',
        'seller_step_1_text' => 'أضف ملف عملك الشعار وبيانات التواصل خلال دقائق.',
        'seller_step_2_title' => 'أدرج منتجاتك',
        'seller_step_2_text' => 'أدر المنتجات والأسعار وحالة المخزون والفئات بنفسك.',
        'seller_step_3_title' => 'تابع نموك',
        'seller_step_3_text' => 'شاهد إحصاءات الزوار وتقارير المبيعات مباشرة من لوحتك.',
        'contact_title' => 'تواصل معنا',
        'contact_text' => 'لديك سؤال أو ملاحظة أو تريد إدراج متجرك على ريونيك؟ يسعدنا سماع رأيك.',
        'contact_whatsapp' => 'واتساب',
        'contact_call' => 'اتصال',
        'contact_email' => 'البريد الإلكتروني',
        'back_home' => 'العودة إلى السوق',
        'footer' => 'ريونيك — نموذج سوق محلي',
    ],
];

function t($key, $lang, $T) {
    return $T[$lang][$key] ?? $T['en'][$key] ?? $key;
}
?>
<!doctype html>
<html lang="<?= e($lang) ?>" dir="<?= in_array($lang, ['ar', 'ku'], true) ? 'rtl' : 'ltr' ?>">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title><?= e(t('site_title', $lang, $T)) ?></title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root{
      color-scheme: dark;
      --bg:#071021; --bg-2:#071827; --card:rgba(255,255,255,0.03); --card-2:rgba(255,255,255,0.02);
      --text:#e6eef8; --muted:#94a3b8; --border:rgba(255,255,255,0.08); --border-strong:rgba(255,255,255,0.12);
      --btn-text:#e6eef8; --pill-bg:rgba(255,255,255,0.03); --link:#9fb0c8;
    }
    body[data-theme="light"]{
      color-scheme: light;
      --bg:#f5f7fb; --bg-2:#ffffff; --card:#ffffff; --card-2:#f8fafc;
      --text:#0f172a; --muted:#64748b; --border:rgba(15,23,42,0.08); --border-strong:rgba(15,23,42,0.12);
      --btn-text:#0f172a; --pill-bg:rgba(15,23,42,0.04); --link:#475569;
    }
    body{ background: linear-gradient(180deg,var(--bg) 0%, var(--bg-2) 100%); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial; }
    .card{ background: linear-gradient(180deg, var(--card), var(--card-2)); border:1px solid var(--border); padding:14px; border-radius:12px; box-shadow:0 6px 18px rgba(2,6,23,0.08); }
    .small-muted{ color:var(--muted); font-size:13px; }
    .btn-ghost{ background:transparent; border:1px solid var(--border); padding:6px 10px; border-radius:10px; color:var(--btn-text); transition:all .2s ease; }
    .btn-ghost:hover{ background:rgba(255,255,255,0.05); transform:translateY(-1px); }
    body[data-theme="light"] .btn-ghost:hover{ background:rgba(15,23,42,0.05); }
    .btn-primary{ display:inline-flex; align-items:center; justify-content:center; gap:.5rem; background:linear-gradient(90deg, #4f46e5, #14b8a6); color:#fff; border:none; padding:.7rem 1.3rem; border-radius:999px; font-weight:700; box-shadow:0 18px 40px rgba(59,130,246,0.22); transition:transform .2s ease, opacity .2s ease; text-decoration:none; }
    .btn-primary:hover{ transform:translateY(-1px); opacity:.98; }
    .pill{ background:var(--pill-bg); padding:6px 10px;border-radius:999px;font-size:13px; }
    .input-dark{ background:var(--input-bg,transparent); border:1px solid var(--border); padding:8px 10px;border-radius:8px;color:var(--text); }
    .link-muted{ color:var(--link); text-decoration:none; }
    .topbar{ position:sticky; top:18px; z-index:40; background:rgba(255,255,255,0.94); backdrop-filter:blur(20px); border:1px solid rgba(15,23,42,0.08); border-radius:28px; padding:18px 24px; box-shadow:0 30px 70px rgba(15,23,42,0.12); }
    body[data-theme="dark"] .topbar{ background:rgba(15,23,42,0.92); border-color:rgba(255,255,255,0.1); }
    .topbar .brand{ display:flex; align-items:center; gap:0.9rem; }
    .brand-logo{ width:48px; height:48px; border-radius:18px; border:1px solid rgba(15,23,42,0.1); box-shadow:0 16px 40px rgba(59,130,246,0.12); object-fit:cover; }
    .brand-title{ font-size:1.05rem; font-weight:700; letter-spacing:-0.03em; }
    .brand-subtitle{ color:var(--muted); font-size:0.9rem; }
    .site-nav{ display:none; }
    @media (min-width: 1280px){ .site-nav{ display:flex; align-items:center; gap:2rem; } }
    .site-nav a{ color:var(--text); opacity:0.78; font-size:0.95rem; font-weight:600; transition:opacity .2s ease, transform .2s ease; }
    .site-nav a:hover, .site-nav a.active{ opacity:1; transform:translateY(-1px); }
    .site-nav a.active{ color:#14b8a6; }
    .topbar-actions{ display:flex; flex-wrap:wrap; gap:0.75rem; align-items:center; justify-content:flex-end; }
    .about-hero{ position:relative; overflow:hidden; border-radius:32px; background:linear-gradient(180deg, rgba(255,255,255,0.96), rgba(245,249,255,0.94)); border:1px solid rgba(148,163,184,0.18); padding:3.5rem 2rem; margin-top:1.5rem; text-align:center; }
    .about-hero::before{ content:''; position:absolute; inset:0; background:radial-gradient(circle at 14% 22%, rgba(59,130,246,0.22), transparent 20%), radial-gradient(circle at 90% 15%, rgba(168,85,247,0.14), transparent 16%); pointer-events:none; }
    .about-hero > *{ position:relative; z-index:1; }
    .about-hero h1{ font-size:clamp(1.9rem, 3.4vw, 2.9rem); line-height:1.15; margin:0 auto; color:#071825; letter-spacing:-0.03em; max-width:44rem; }
    .about-hero p{ margin:1.25rem auto 0; color:#475569; font-size:1.05rem; line-height:1.75; max-width:38rem; }
    .chip-badge{ display:inline-block; background:linear-gradient(135deg, rgba(99,102,241,0.24), rgba(45,212,191,0.18)); border:1px solid rgba(255,255,255,0.16); color:#071825; padding:8px 14px; border-radius:999px; font-size:13px; font-weight:700; box-shadow:0 8px 20px rgba(2,6,23,0.16); }
    .step-card{ background: linear-gradient(180deg, var(--card), var(--card-2)); border:1px solid var(--border); border-radius:14px; padding:16px; }
    .step-num{ display:inline-flex; align-items:center; justify-content:center; width:28px; height:28px; border-radius:999px; background:linear-gradient(90deg, #4f46e5, #14b8a6); color:#fff; font-weight:700; font-size:13px; margin-bottom:.6rem; }
  </style>
</head>
<body data-theme="<?= e($theme) ?>">
  <div class="max-w-6xl mx-auto p-6">
    <div class="topbar mb-6">
      <div class="flex flex-col gap-6 xl:flex-row xl:items-center xl:justify-between">
        <div class="flex flex-col gap-4 xl:flex-row xl:items-center xl:gap-6">
          <a href="index.php?lang=<?= urlencode($lang) ?>" class="flex items-center gap-3">
            <img src="uploads/logo.svg" alt="Reyonic logo" class="brand-logo">
            <div>
              <div class="brand-title">Reyonic</div>
              <div class="brand-subtitle"><?= e(t('site_subtitle', $lang, $T)) ?></div>
            </div>
          </a>
          <nav class="site-nav">
            <a href="index.php?lang=<?= urlencode($lang) ?>"><?= e(t('nav_home', $lang, $T)) ?></a>
            <a href="index.php?q=&lang=<?= urlencode($lang) ?>"><?= e(t('nav_products', $lang, $T)) ?></a>
            <a href="about.php?lang=<?= urlencode($lang) ?>" class="active"><?= e(t('nav_about', $lang, $T)) ?></a>
            <a href="about.php?lang=<?= urlencode($lang) ?>#contact"><?= e(t('nav_contact', $lang, $T)) ?></a>
          </nav>
        </div>

        <div class="topbar-actions">
          <form method="get" class="flex items-center gap-2">
            <input type="hidden" name="lang" value="<?= e($lang) ?>">
            <input type="hidden" name="theme" value="<?= $theme === 'dark' ? 'light' : 'dark' ?>">
            <button type="submit" class="btn-ghost" title="<?= e(t('theme_toggle', $lang, $T)) ?>">
              <?= $theme === 'dark' ? '☀️ ' . e(t('light', $lang, $T)) : '🌙 ' . e(t('dark', $lang, $T)) ?>
            </button>
          </form>
          <form method="get" class="flex items-center gap-2">
            <input type="hidden" name="theme" value="<?= e($theme) ?>">
            <label class="small-muted text-xs"><?= e(t('language', $lang, $T)) ?></label>
            <select name="lang" class="input-dark w-28" onchange="this.form.submit()">
              <?php foreach ($availableLanguages as $code => $label): ?>
                <option value="<?= e($code) ?>" <?= $lang === $code ? 'selected' : '' ?>><?= e($label) ?></option>
              <?php endforeach; ?>
            </select>
          </form>
          <?php if ($auth): ?>
            <div class="pill"><?= e($auth['name']) ?></div>
            <?php if ($auth['type'] === 'admin'): ?>
              <a href="index.php?admin=1&lang=<?= urlencode($lang) ?>" class="btn-primary"><?= e(t('admin', $lang, $T)) ?></a>
            <?php elseif ($auth['type'] === 'seller'): ?>
              <a href="index.php?my_shop=1&lang=<?= urlencode($lang) ?>" class="btn-primary"><?= e(t('my_shop', $lang, $T)) ?></a>
            <?php endif; ?>
          <?php else: ?>
            <a href="index.php?lang=<?= urlencode($lang) ?>" class="btn-primary"><?= e(t('login', $lang, $T)) ?></a>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <section class="about-hero">
      <span class="chip-badge"><?= e(t('about_badge', $lang, $T)) ?></span>
      <h1 class="font-semibold"><?= e(t('about_title', $lang, $T)) ?></h1>
      <p><?= e(t('about_lead', $lang, $T)) ?></p>
      <div class="mt-6">
        <a href="index.php?q=&lang=<?= urlencode($lang) ?>" class="btn-primary"><?= e(t('back_home', $lang, $T)) ?></a>
      </div>
    </section>

    <section class="card mt-6">
      <div class="font-semibold text-lg mb-2"><?= e(t('mission_title', $lang, $T)) ?></div>
      <p class="small-muted leading-7"><?= e(t('mission_text', $lang, $T)) ?></p>
    </section>

    <section class="mt-6">
      <div class="font-semibold text-lg mb-3"><?= e(t('how_title', $lang, $T)) ?></div>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="card">
          <div class="font-semibold mb-3"><?= e(t('for_customers', $lang, $T)) ?></div>
          <div class="space-y-3">
            <div class="step-card">
              <div class="step-num">1</div>
              <div class="font-semibold text-sm"><?= e(t('customer_step_1_title', $lang, $T)) ?></div>
              <div class="small-muted text-sm mt-1"><?= e(t('customer_step_1_text', $lang, $T)) ?></div>
            </div>
            <div class="step-card">
              <div class="step-num">2</div>
              <div class="font-semibold text-sm"><?= e(t('customer_step_2_title', $lang, $T)) ?></div>
              <div class="small-muted text-sm mt-1"><?= e(t('customer_step_2_text', $lang, $T)) ?></div>
            </div>
            <div class="step-card">
              <div class="step-num">3</div>
              <div class="font-semibold text-sm"><?= e(t('customer_step_3_title', $lang, $T)) ?></div>
              <div class="small-muted text-sm mt-1"><?= e(t('customer_step_3_text', $lang, $T)) ?></div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="font-semibold mb-3"><?= e(t('for_sellers', $lang, $T)) ?></div>
          <div class="space-y-3">
            <div class="step-card">
              <div class="step-num">1</div>
              <div class="font-semibold text-sm"><?= e(t('seller_step_1_title', $lang, $T)) ?></div>
              <div class="small-muted text-sm mt-1"><?= e(t('seller_step_1_text', $lang, $T)) ?></div>
            </div>
            <div class="step-card">
              <div class="step-num">2</div>
              <div class="font-semibold text-sm"><?= e(t('seller_step_2_title', $lang, $T)) ?></div>
              <div class="small-muted text-sm mt-1"><?= e(t('seller_step_2_text', $lang, $T)) ?></div>
            </div>
            <div class="step-card">
              <div class="step-num">3</div>
              <div class="font-semibold text-sm"><?= e(t('seller_step_3_title', $lang, $T)) ?></div>
              <div class="small-muted text-sm mt-1"><?= e(t('seller_step_3_text', $lang, $T)) ?></div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section id="contact" class="card mt-6">
      <div class="font-semibold text-lg mb-2"><?= e(t('contact_title', $lang, $T)) ?></div>
      <p class="small-muted mb-4"><?= e(t('contact_text', $lang, $T)) ?></p>
      <div class="flex flex-wrap gap-2">
        <a class="inline-flex items-center gap-1 rounded-full border border-emerald-400/30 bg-emerald-500/10 px-3 py-1.5 text-sm font-semibold text-emerald-300 hover:bg-emerald-500/20" href="<?= e(whatsappLink($defaultPhone, 'Hello, I have a question about Reyonic.')) ?>" target="_blank" rel="noopener noreferrer">💬 <?= e(t('contact_whatsapp', $lang, $T)) ?></a>
        <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="tel:<?= e($defaultPhone) ?>">📞 <?= e(t('contact_call', $lang, $T)) ?></a>
        <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="mailto:<?= e($defaultEmail) ?>">✉️ <?= e(t('contact_email', $lang, $T)) ?></a>
      </div>
    </section>

    <footer class="mt-8 text-center small-muted">
      <?= e(t('footer', $lang, $T)) ?>
    </footer>
  </div>
</body>
</html>
