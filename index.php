<?php
require __DIR__ . '/security.php';
bootstrapSecureSession();
sendSecurityHeaders();
$dbHost = '127.0.0.1';
$dbName = 'reyonic_mvp_dark';
$dbUser = 'root';
$dbPass = ''; // XAMPP default empty
$defaultPhone = '07701992299';
$defaultLogo = 'data:image/svg+xml;utf8,' . rawurlencode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 160"><rect width="160" height="160" rx="36" fill="#111827"/><circle cx="80" cy="80" r="52" fill="#0f766e"/><path d="M58 58h44v44H58z" fill="#f8fafc" fill-opacity="0.95"/><path d="M72 72h16v16H72z" fill="#14b8a6"/><path d="M58 58l22 22L80 80 58 58z" fill="#38bdf8" fill-opacity="0.9"/><path d="M102 58l-22 22L80 80l22-22z" fill="#818cf8" fill-opacity="0.9"/></svg>');

define('ADMIN_EMAIL', 'reyonicapp@gmail.com');
define('ADMIN_PASSWORD_MIN_LENGTH', 12);
define('ADMIN_PASSWORD_COMPLEXITY_PATTERN', '/(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{12,}/');

/* -------------------------
   PDO Connection
   ------------------------- */
try {
    $pdo = new PDO("mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4", $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Exception $e) {
    error_log('DB connection failed: ' . $e->getMessage());
    http_response_code(500);
    echo "<h2>We're having a technical issue. Please try again shortly.</h2>";
    exit;
}

// Now that $pdo exists, ensure security-related tables/columns
ensureSecurityTables($pdo);
ensureAdminSecurityColumns($pdo);
lockDownUploadsFolder(__DIR__ . DIRECTORY_SEPARATOR . 'uploads');

// Start session after session settings were applied
session_start();

function ensureColumn(PDO $pdo, string $table, string $column, string $definition): void {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?");
    $stmt->execute([$table, $column]);
    if ((int) $stmt->fetchColumn() === 0) {
        $pdo->exec("ALTER TABLE `{$table}` ADD COLUMN `{$column}` {$definition}");
    }
}

function ensureWorkspaceSchema(PDO $pdo): void {
    ensureColumn($pdo, 'workspaces', 'description', 'TEXT NULL');
    ensureColumn($pdo, 'workspaces', 'address', 'VARCHAR(255) NULL');
    ensureColumn($pdo, 'workspaces', 'cover_image', 'VARCHAR(255) NULL');
    ensureColumn($pdo, 'workspaces', 'social_links', 'TEXT NULL');
    ensureColumn($pdo, 'workspaces', 'business_hours', 'TEXT NULL');
    ensureColumn($pdo, 'workspaces', 'website', 'VARCHAR(255) NULL');
    ensureColumn($pdo, 'workspaces', 'primary_color', 'VARCHAR(32) NULL');
    ensureColumn($pdo, 'workspaces', 'secondary_color', 'VARCHAR(32) NULL');
    ensureColumn($pdo, 'workspaces', 'theme_color', 'VARCHAR(32) NULL');
    ensureColumn($pdo, 'categories', 'parent_id', 'INT NULL');
    ensureColumn($pdo, 'products', 'sku', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'products', 'stock_status', 'VARCHAR(50) NOT NULL DEFAULT "in_stock"');
    ensureColumn($pdo, 'products', 'featured', 'TINYINT(1) NOT NULL DEFAULT 0');
    ensureColumn($pdo, 'products', 'gallery_images', 'TEXT NULL');
    ensureColumn($pdo, 'products', 'updated_at', 'DATETIME NULL');
    ensureColumn($pdo, 'products', 'brand', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'products', 'tags', 'TEXT NULL');
}

function ensureSubscriptionSchema(PDO $pdo): void {
    ensureColumn($pdo, 'users', 'subscription_status', 'VARCHAR(50) NOT NULL DEFAULT "trial"');
    ensureColumn($pdo, 'users', 'subscription_plan', 'VARCHAR(50) NULL');
    ensureColumn($pdo, 'users', 'subscription_expires_at', 'DATETIME NULL');
    ensureColumn($pdo, 'users', 'subscription_renewal_at', 'DATETIME NULL');
    ensureColumn($pdo, 'users', 'subscription_started_at', 'DATETIME NULL');
    ensureColumn($pdo, 'users', 'subscription_price', 'DECIMAL(10,2) NOT NULL DEFAULT 0');
    ensureColumn($pdo, 'users', 'subscription_currency', 'VARCHAR(10) NOT NULL DEFAULT "IQD"');
    ensureColumn($pdo, 'users', 'subscription_last_payment_id', 'INT NULL');
    ensureColumn($pdo, 'users', 'seller_status', 'VARCHAR(20) NOT NULL DEFAULT "approved"');

    $pdo->exec("CREATE TABLE IF NOT EXISTS subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id INT NOT NULL,
        user_id INT NOT NULL,
        plan_key VARCHAR(50) NOT NULL,
        plan_name VARCHAR(100) NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'trial_active',
        trial_used TINYINT(1) NOT NULL DEFAULT 0,
        price DECIMAL(10,2) NOT NULL DEFAULT 0,
        currency VARCHAR(10) NOT NULL DEFAULT 'IQD',
        started_at DATETIME NULL,
        expires_at DATETIME NULL,
        renews_at DATETIME NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id INT NOT NULL,
        user_id INT NOT NULL,
        plan_key VARCHAR(50) NOT NULL,
        plan_name VARCHAR(100) NOT NULL,
        amount DECIMAL(10,2) NOT NULL DEFAULT 0,
        currency VARCHAR(10) NOT NULL DEFAULT 'IQD',
        payment_method VARCHAR(50) NOT NULL DEFAULT 'fib',
        status VARCHAR(50) NOT NULL DEFAULT 'paid',
        invoice_number VARCHAR(100) NULL,
        invoice_path VARCHAR(255) NULL,
        paid_at DATETIME NOT NULL,
        notes TEXT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS analytics_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id INT NOT NULL,
        event_type VARCHAR(50) NOT NULL,
        product_id INT NULL,
        device_type VARCHAR(50) NULL,
        city VARCHAR(100) NULL,
        country VARCHAR(100) NULL,
        created_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS sales (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id INT NOT NULL,
        product_id INT NULL,
        quantity INT NOT NULL DEFAULT 1,
        unit_price DECIMAL(10,2) NOT NULL DEFAULT 0,
        total_price DECIMAL(12,2) NOT NULL DEFAULT 0,
        sale_date DATE NOT NULL,
        notes TEXT NULL,
        created_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS inquiries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id INT NOT NULL,
        customer_name VARCHAR(150) NULL,
        customer_email VARCHAR(150) NULL,
        customer_phone VARCHAR(50) NULL,
        message TEXT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'new',
        created_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function ensureUserRoleSchema(PDO $pdo): void {
    ensureColumn($pdo, 'users', 'role', 'VARCHAR(50) NOT NULL DEFAULT "customer"');
    $pdo->exec("UPDATE users SET role = 'seller' WHERE workspace_id > 0 AND (role IS NULL OR role = '')");
    $pdo->exec("UPDATE users SET role = 'customer' WHERE workspace_id = 0 AND (role IS NULL OR role = '')");
}

ensureWorkspaceSchema($pdo);
ensureSubscriptionSchema($pdo);
ensureUserRoleSchema($pdo);

function hashPassword(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT);
}

function verifyPassword(string $password, string $storedHash): bool {
    if ($storedHash === '') {
        return false;
    }
    $info = password_get_info($storedHash);
    if ($info['algo'] !== 0) {
        return password_verify($password, $storedHash);
    }
    return hash_equals($storedHash, $password);
}

function isStrongPassword(string $password): bool {
    return preg_match(ADMIN_PASSWORD_COMPLEXITY_PATTERN, $password) === 1;
}

function ensureSingleAdmin(PDO $pdo): void {
    $adminEmail = strtolower(trim(ADMIN_EMAIL));
    if ($adminEmail === '') {
        return;
    }
    $stmt = $pdo->prepare("UPDATE users SET role = CASE WHEN workspace_id > 0 THEN 'seller' ELSE 'customer' END WHERE role = 'admin' AND LOWER(email) != ?");
    $stmt->execute([$adminEmail]);
}

/* -------------------------
   Simple session auth (prototype)
   ------------------------- */
// session already started above; use session for auth
$auth = $_SESSION['auth'] ?? null; // ['type'=>'seller'|'customer','id'=>int,'name'=>string]

/* -------------------------
   Theme support
   ------------------------- */
$theme = strtolower($_GET['theme'] ?? ($_COOKIE['theme'] ?? 'dark'));
if (!in_array($theme, ['dark', 'light'], true)) {
    $theme = 'dark';
}
setcookie('theme', $theme, time() + 60 * 60 * 24 * 365, '/', '', false, true);

/* -------------------------
   Multi-language support
   ------------------------- */
$availableLanguages = ['ku' => 'Kurdish', 'en' => 'English', 'ar' => 'Arabic'];
$defaultLanguage = 'ku';
$lang = strtolower($_GET['lang'] ?? $_SESSION['lang'] ?? $defaultLanguage);
if (!isset($availableLanguages[$lang])) {
    $lang = $defaultLanguage;
}
$_SESSION['lang'] = $lang;

$translations = [
    'en' => [
        'site_title' => 'Reyonic — Marketplace',
        'site_subtitle' => 'Local marketplace',
        'search_placeholder' => 'Search businesses or products',
        'search_label' => 'Search',
        'search_by_name' => 'Search by name',
        'location_label' => 'Location',
        'my_shop' => 'My shop',
        'login' => 'Login',
        'logout' => 'Logout',
        'products_count' => '%d products',
        'see_products' => 'See products',
        'contact' => 'Contact',
        'seller_dashboard' => 'Seller Dashboard',
        'workspace_id' => 'Workspace ID',
        'add_product' => 'Add Product',
        'your_products' => 'Your Products',
        'no_products' => 'No products yet.',
        'product_added' => 'Product added.',
        'category' => 'Category',
        'category_placeholder' => 'Category name (new or existing)',
        'product_name' => 'Product name',
        'price' => 'Price (IQD)',
        'image_url' => 'Image URL',
        'description' => 'Description',
        'add_button' => 'Add',
        'login_title' => 'Login',
        'close' => 'Close',
        'customer_quick' => 'Customer (Quick)',
        'customer_name' => 'Name',
        'customer_email' => 'Email',
        'customer_button' => 'Continue as Customer',
        'seller' => 'Seller',
        'seller_password' => 'Password',
        'seller_button' => 'Login as Seller',
        'seller_helper' => 'Only admins can create seller accounts; ask the admin to add you and approve your seller status.',
        'invalid_seller' => 'Invalid seller credentials (prototype).',
        'footer' => 'Reyonic — Local marketplace prototype',
        'language' => 'Language',
        'theme_toggle' => 'Toggle theme',
        'hero_title' => 'Discover trusted local shops',
        'hero_subtitle' => 'Browse modern stores, find great products, and connect easily with sellers in one polished marketplace experience.',
        'hero_cta' => 'Explore now',
        'hero_secondary' => 'Become a seller',
        'featured_stores' => 'Featured stores',
        'featured_subtitle' => 'A curated list of local businesses ready to impress.',
        'clear_search' => 'Clear search',
        'empty_title' => 'No stores matched your search',
        'empty_subtitle' => 'Try another keyword or browse the featured categories above.',
        'categories_title' => 'Popular categories',
        'category_fashion' => 'Fashion',
        'category_electronics' => 'Electronics',
        'category_food' => 'Food',
        'category_beauty' => 'Beauty',
        'location_sulaimani' => 'Sulaimani',
        'location_erbil' => 'Erbil',
        'stats_shops' => 'Local shops',
        'stats_products' => 'Products listed',
        'stats_fast' => 'Fast contact',
        'payment_title' => 'Pay with FIB or FastPay',
        'payment_methods' => 'Payment options',
        'pay_with_fib' => 'Pay with FIB',
        'pay_with_fastpay' => 'Pay with FastPay',
        'payment_note' => 'Choose a payment method and confirm the order in WhatsApp.',
        'admin' => 'Admin',
        'light' => 'Light',
        'dark' => 'Dark',
        'hero_badge' => 'No account needed • Browse shops and connect with sellers quickly',
        'admin_dashboard' => 'Admin dashboard',
        'admin_subtitle' => 'Platform summary and workspace management.',
        'refresh' => 'Refresh',
        'public_view' => 'Public view',
        'stat_workspaces' => 'Workspaces',
        'stat_products' => 'Products',
        'stat_sales' => 'Sales',
        'stat_revenue' => 'Revenue',
        'search_workspaces' => 'Search workspaces',
        'search_btn' => 'Search',
        'table_slug' => 'Slug',
        'table_name' => 'Name',
        'table_actions' => 'Actions',
        'no_workspaces' => 'No workspaces found.',
        'view' => 'View',
        'delete' => 'Delete',
        'delete_workspace_confirm' => 'Delete workspace and all related data?',
        'brand_label' => 'Brand',
        'qr_code' => 'QR code',
        'qr_print_ready' => 'Print-ready QR for the storefront',
        'store_categories' => 'Categories',
        'general' => 'General',
        'search_products' => 'Search products',
        'all_categories' => 'All categories',
        'all_subcategories' => 'All subcategories',
        'all_brands' => 'All brands',
        'all_tags' => 'All tags',
        'sort_newest' => 'Newest',
        'sort_price_asc' => 'Price: low to high',
        'sort_price_desc' => 'Price: high to low',
        'sort_oldest' => 'Oldest',
        'apply_filters' => 'Apply filters',
        'reset' => 'Reset',
        'contact_social' => 'Contact & social',
        'no_social' => 'No social links yet.',
        'visit_website' => 'Visit website',
        'shop_profile' => 'Store profile',
        'default_shop_bio' => 'This store has a quick Reyonic profile for products and orders.',
        'location_map' => 'Location map',
        'open_maps' => 'Tap to open in Google Maps.',
        'quick_actions' => 'Quick actions',
        'browse' => 'Browse',
        'share_btn' => 'Share',
        'copy_link' => 'Copy link',
        'contact_store' => 'Contact business',
        'contact_store_title' => 'Contact this business',
        'contact_store_desc' => 'This page is for browsing store profiles and product portfolios. Contact the business for availability or viewing details.',
        'no_products_store' => 'This store has no products yet.',
        'view_details' => 'View details',
        'no_image' => 'No image',
        'product_details' => 'Product details',
        'back_to_store' => 'Back to store',
        'sku_label' => 'SKU',
        'na' => 'N/A',
        'availability' => 'Availability',
        'share_product' => 'Share product',
        'share_whatsapp' => 'Share on WhatsApp',
        'product_link' => 'Product link',
        'cover_preview' => 'Cover image preview',
        'shop_desc_preview' => 'Your shop description preview appears here.',
        'social_label' => 'Social',
        'profile_preview' => 'Profile preview',
        'shop_snapshot' => 'Shop snapshot',
        'shop_snapshot_desc' => 'This is how your store appears to customers on Reyonic.',
        'uncategorized' => 'Uncategorized',
        'add_products_feed' => 'No products yet. Add products to build your shop feed.',
        'not_set' => 'Not set yet',
        'shop_name_label' => 'Shop name',
        'business_name_label' => 'Business name',
        'description_label' => 'Description',
        'website_label' => 'Website',
        'address_label' => 'Address',
        'hours_label' => 'Hours',
        'social_links_label' => 'Social links',
        'improve_profile' => 'Improve your store profile presentation',
        'profile_theme' => 'Profile theme',
        'primary_color' => 'Primary color',
        'secondary_color' => 'Secondary color',
        'logo_or_url' => 'Or logo URL',
        'cover_url' => 'Cover image URL',
        'shop_description' => 'Store description',
        'phone_label' => 'Phone',
        'custom_url' => 'Custom store URL',
        'save_shop_profile' => 'Save store profile',
        'share_profile' => 'Share your profile',
        'public_link' => 'Public link',
        'copy' => 'Copy',
        'copied' => 'Copied',
        'download_qr' => 'Download QR',
        'quick_shortcuts' => 'Quick shortcuts',
        'products_nav' => 'Products',
        'categories_nav' => 'Categories',
        'analytics_nav' => 'Analytics',
        'settings_nav' => 'Settings',
        'orders_nav' => 'Orders',
        'public_profile' => 'Public profile',
        'preview_below' => 'Profile preview below',
        'brand_color_hint' => 'A brand color version with your current theme.',
        'color_change_hint' => 'Changing the top color updates the preview.',
        'refresh_dashboard' => 'Refresh',
        'preview_public_shop' => 'Preview public shop',
        'total_visitors' => 'Total visits',
        'product_views_label' => 'Product views',
        'daily_visitors' => 'Daily visits',
        'monthly_visitors' => 'Monthly visits',
        'top_viewed' => 'Top viewed pages',
        'no_product_views' => 'No product views yet.',
        'views_count' => '%d views',
        'popular_categories_analytics' => 'Popular categories',
        'no_category_activity' => 'No category activity yet.',
        'device_types' => 'Device types',
        'no_device_data' => 'No device data yet.',
        'visits_count' => '%d visits',
        'visitor_locations' => 'Visitor locations',
        'no_location_data' => 'No location data yet.',
        'unknown' => 'Unknown',
        'sales_overview' => 'Sales overview',
        'lifetime_revenue' => 'Lifetime revenue',
        'sales_records' => 'Sales records',
        'units_sold' => 'Units sold',
        'this_month' => 'This month',
        'from_date' => 'From',
        'to_date' => 'To',
        'sales_search' => 'Search sales',
        'sales_search_ph' => 'Product name, SKU, notes',
        'filter' => 'Filter',
        'today' => 'Today',
        'current_week' => 'Current week',
        'current_month' => 'Current month',
        'current_year' => 'Current year',
        'vs_yesterday' => 'vs yesterday',
        'vs_last_week' => 'vs last week',
        'vs_last_month' => 'vs last month',
        'vs_last_year' => 'vs last year',
        'no_prior_data' => 'No prior data',
        'best_selling' => 'Best-selling products',
        'no_sales_yet' => 'No sales recorded yet.',
        'pcs' => 'pcs',
        'category_revenue' => 'Category revenue',
        'no_category_revenue' => 'No category revenue yet.',
        'revenue_30_days' => 'Revenue (Last 30 days)',
        'revenue_monthly' => 'Revenue (Monthly)',
        'record_sale' => 'Record a sale',
        'product_select' => 'Product',
        'general_item' => 'General item',
        'quantity' => 'Quantity',
        'unit_price' => 'Unit price (IQD)',
        'sale_date' => 'Sale date',
        'notes' => 'Notes',
        'notes_ph' => 'Optional notes',
        'record_sale_btn' => 'Record sale',
        'recent_sales' => 'Recent sales',
        'no_sales_period' => 'No sales found for this period.',
        'no_category' => 'No category',
        'qty_label' => 'Qty',
        'notes_label' => 'Notes',
        'business_management' => 'Business management',
        'store_health' => 'Store health',
        'store_health_desc' => 'This dashboard helps you manage your store profile, inventory, and customer communication.',
        'recent_activity' => 'Recent activity',
        'recent_activity_desc' => 'Browse listings, product views, and new contact activity here.',
        'edit_product' => 'Edit product',
        'subcategory' => 'Subcategory',
        'subcategory_ph' => 'Optional subcategory',
        'brand_ph' => 'Brand',
        'featured' => 'Featured',
        'tags_ph' => 'sale, new, featured',
        'update_product' => 'Update product',
        'delete_product' => 'Delete',
        'edit' => 'Edit',
        'featured_badge' => 'Featured',
        'store_profile_setup' => 'Store profile setup',
        'logo_image' => 'Logo image',
        'save_profile' => 'Save profile',
        'notifications_comm' => 'Notifications & Communication',
        'inquiry_name_ph' => 'Your name',
        'inquiry_email_ph' => 'Email',
        'inquiry_phone_ph' => 'Phone',
        'inquiry_message_ph' => 'How can we help?',
        'send_inquiry' => 'Send inquiry',
        'call' => 'Call',
        'email_label' => 'Email',
        'recent_inquiries' => 'Recent inquiries',
        'no_inquiries' => 'No inquiries yet.',
        'customer' => 'Customer',
        'communication_history' => 'Communication history',
        'comm_history_hint' => 'Review recent inquiries, enquiries, and shop updates here.',
        'role_seller' => 'Seller',
        'role_customer' => 'Customer',
        'role_admin' => 'Admin',
        'stock_in_stock' => 'In stock',
        'stock_out_of_stock' => 'Out of stock',
        'stock_low_stock' => 'Low stock',
        'product_deleted' => 'Product deleted.',
        'product_updated' => 'Product updated.',
        'sale_recorded' => 'Sale recorded successfully.',
        'sale_invalid' => 'Please enter a valid unit price and sale date.',
        'sale_deleted' => 'Sale deleted.',
        'image_upload_failed' => 'Image upload failed.',
        'image_too_large' => 'Please upload an image smaller than 2MB.',
        'inquiry_received' => 'Inquiry received. We will contact you soon.',
        'subscription_disabled' => 'Subscription purchases are disabled in this business dashboard.',
        'admin_deleted' => 'Workspace and related data deleted.',
        'chart_revenue' => 'Revenue (IQD)',
        'product_num' => 'Product #%d',
        'stock_status' => 'Stock status',
        'stock_preorder' => 'Pre-order',
        'tags' => 'Tags',
        'main_image' => 'Main image',
        'image_url_or' => 'Or image URL',
        'gallery_images' => 'Gallery images',
        'save_changes' => 'Save changes',
        'cancel' => 'Cancel',
    ],
    'ku' => [
        'site_title' => 'ڕێۆنیک — بازاڕیەکی ناوخۆیی',
        'site_subtitle' => 'بازاڕی ناوخۆیی',
        'search_placeholder' => 'گەڕان لە کۆمپانیا و بەرهەمەکان',
        'search_label' => 'گەڕان',
        'search_by_name' => 'گەڕان بە ناو',
        'location_label' => 'شوێن',
        'my_shop' => 'دوکانەکەم',
        'login' => 'چوونەژوورەوە',
        'logout' => 'دەرچوون',
        'products_count' => '%d بەرهەم',
        'see_products' => 'بینینی بەرهەمەکان',
        'contact' => 'پەیوەندی',
        'seller_dashboard' => 'داشبۆردی فرۆشیار',
        'workspace_id' => 'ناسنامەی وورک‌اسپەیس',
        'add_product' => 'زیادکردنی بەرهەم',
        'your_products' => 'بەرهەمەکانت',
        'no_products' => 'هێشتا بەرهەم نییە.',
        'product_added' => 'بەرهەم زیادکرا.',
        'category' => 'هاوپۆلە',
        'category_placeholder' => 'ناوی هاوپۆل (نوێ یان هەبوو)',
        'product_name' => 'ناوی بەرهەم',
        'price' => 'نرخ (IQD)',
        'image_url' => 'URLی وێنە',
        'description' => 'وەسف',
        'add_button' => 'زیادکردن',
        'login_title' => 'چوونەژوورەوە',
        'close' => 'داخستن',
        'customer_quick' => 'کڕیار (خێرا)',
        'customer_name' => 'ناو',
        'customer_email' => 'ئیمەیڵ',
        'customer_button' => 'بەردەوام بووە وەک کڕیار',
        'seller' => 'فرۆشیار',
        'seller_password' => 'ژمارەی نهێنی',
        'seller_button' => 'چوونەژوورەوە وەک فرۆشیار',
        'seller_helper' => 'تەنها ئەدمین دەتوانێت هەژمار فرۆشیارەکان دروست بکات؛ تکایە داواکاری بکە بۆ ئەدمین بۆ پەسەندکردن.',
        'invalid_seller' => 'زانیارییەکانی فرۆشیار نادروستە (پڕۆتۆتایپ).',
        'footer' => 'ڕێۆنیک — پڕۆتۆتایپی بازاڕی ناوخۆیی',
        'language' => 'زمان',
        'theme_toggle' => 'گۆڕینی ڕووکاری',
        'hero_title' => 'کۆکردنەوەی دوکانە ناوخۆییەکانی متمانەدار',
        'hero_subtitle' => 'لە یەک بازرگانییەکی ڕوون و جواندا دوکانەکانی ناوخۆیی بگەڕێنەوە و بە خێرایی پەیوەندیت بەم فرۆشیارانە بکە.',
        'hero_cta' => 'ئێستا بگەڕێ',
        'hero_secondary' => 'ببە فرۆشیار',
        'featured_stores' => 'دوکانە تایبەتمەندەکان',
        'featured_subtitle' => 'لیستیەکی دیاریکراوی دوکانە ناوخۆییەکان بۆ ئەوەی ڕوون و جوان بێت.',
        'clear_search' => 'سڕینەوەی گەڕان',
        'empty_title' => 'هیچ دوکانێک لە گەڕانەکەتدا نەدۆزرایەوە',
        'empty_subtitle' => 'وشەیەکی تر بنووسە یان سەردانی هاوپۆلەکانی سەرەوە بکە.',
        'categories_title' => 'هاوپۆلە بەناوبانگەکان',
        'category_fashion' => 'پۆشاک',
        'category_electronics' => 'ئەلکترۆنی',
        'category_food' => 'خواردنەوە',
        'category_beauty' => 'جوانکاری',
        'location_sulaimani' => 'سلێمانی',
        'location_erbil' => 'هەولێر',
        'stats_shops' => 'دوکانە ناوخۆییەکان',
        'stats_products' => 'بەرهەمە نادراوەکان',
        'stats_fast' => 'پەیوەندی خێرا',
        'payment_title' => 'بە FIB یان FastPay بپارێزە',
        'payment_methods' => 'هەڵبژاردەکانی پارەدان',
        'pay_with_fib' => 'بە FIB بپارێزە',
        'pay_with_fastpay' => 'بە FastPay بپارێزە',
        'payment_note' => 'هەڵبژاردەیەک دیاری بکە و داواکارییەکە لە واتسئەپ دڵنیابکەوە.',
        'admin' => 'ئەدمین',
        'light' => 'ڕووناک',
        'dark' => 'تاریک',
        'hero_badge' => 'هیچ هەژمارێک پێویست نییە • دوکانەکان بگەڕێ و بە فرۆشیاران بە خێرایی پەیوەندیت بکە',
        'admin_dashboard' => 'داشبۆردی ئەدمین',
        'admin_subtitle' => 'کورتەی پلاتفۆرم و بەڕێوەبردنی وورک‌اسپەیس.',
        'refresh' => 'نوێکردنەوە',
        'public_view' => 'بینینی گشتی',
        'stat_workspaces' => 'وورک‌اسپەیس',
        'stat_products' => 'بەرهەم',
        'stat_sales' => 'فرۆشتن',
        'stat_revenue' => 'داهات',
        'search_workspaces' => 'گەڕان لە وورک‌اسپەیس',
        'search_btn' => 'گەڕان',
        'table_slug' => 'سلەگ',
        'table_name' => 'ناو',
        'pending_sellers_title' => 'فرۆشیارانی چاودێریکراو',
        'pending_sellers_info' => 'ئەم ژمارەیانه بەم شێوەیە هێشتا لە مۆدێریتی ئەدمینەوە بەردەست نییە.',
        'pending' => 'چاودێریکراو',
        'approve' => 'پەسەندکردن',
        'table_actions' => 'کردارەکان',
        'no_workspaces' => 'هیچ وورک‌اسپەیسێک نەدۆزرایەوە.',
        'view' => 'بینین',
        'delete' => 'سڕینەوە',
        'delete_workspace_confirm' => 'وورک‌اسپەیس و هەموو داتاکانی پەیوەندیدار بسڕدرێنەوە؟',
        'brand_label' => 'مارکە',
        'qr_code' => 'کۆدی QR',
        'qr_print_ready' => 'QR ئامادەی چاپکردن بۆ دوکان',
        'store_categories' => 'هاوپۆلەکان',
        'general' => 'گشتی',
        'search_products' => 'گەڕان لە بەرهەمەکان',
        'all_categories' => 'هەموو هاوپۆلەکان',
        'all_subcategories' => 'هەموو ژێرهاوپۆلەکان',
        'all_brands' => 'هەموو مارکەکان',
        'all_tags' => 'هەموو تاگەکان',
        'sort_newest' => 'نوێترین',
        'sort_price_asc' => 'نرخ: لە کەم بۆ زۆر',
        'sort_price_desc' => 'نرخ: لە زۆر بۆ کەم',
        'sort_oldest' => 'کۆنترین',
        'apply_filters' => 'جێبەجێکردنی فیلتەر',
        'reset' => 'هەڵگرتنەوە',
        'contact_social' => 'پەیوەندیدان و کۆمەڵایەتی',
        'no_social' => 'هێشتا هیچ پەیوەندی کۆمەڵایەتییەک نییە.',
        'visit_website' => 'سەردانی ماڵپەڕ بکە',
        'shop_profile' => 'پڕۆفایلی دوکان',
        'default_shop_bio' => 'ئەم دوکانە پڕۆفایلی خێرا و سادەی Reyonic هەیە بۆ زیادکردنی بەرهەم و داواکاری.',
        'location_map' => 'نەخشەی شوێن',
        'open_maps' => 'بۆ کردنەوە لە Google Maps کرتە بکە.',
        'quick_actions' => 'کردارە خێراکە',
        'browse' => 'گەڕان',
        'share_btn' => 'هاوبەش بکە',
        'copy_link' => 'بەستەر کۆپی بکە',
        'contact_store' => 'پەیوەندی بکە بە کاروبار',
        'contact_store_title' => 'پەیوەندی بکە بە ئەم کاروبارە',
        'contact_store_desc' => 'ئەم لاپەڕە بۆ گەڕان لە پڕۆفایلە دوکانەکان و پۆرتفۆلیۆی بەرهەمەکانە. بۆ وردەکارییەکانی بەردەستبوون یان بینین پەیوەندی بکە بە کاروبار.',
        'no_products_store' => 'ئەم دوکانە هێشتا هیچ بەرهەمێک نییە.',
        'view_details' => 'وردەکاری ببینە',
        'no_image' => 'وێنە نییە',
        'product_details' => 'وردەکاری بەرهەم',
        'back_to_store' => 'گەڕانەوە بۆ دوکان',
        'sku_label' => 'SKU',
        'na' => 'بەردەست نییە',
        'availability' => 'بەردەستبوون',
        'share_product' => 'هاوبەش بکە بەرهەم',
        'share_whatsapp' => 'WhatsApp داهاوبەش بکە',
        'product_link' => 'بەستەری بەرهەم',
        'cover_preview' => 'پێشبینی وێنەی مافەر',
        'shop_desc_preview' => 'پێشبینی وەسفی دوکانەکەت لێرە دەردەکەوێت.',
        'social_label' => 'کۆمەڵایەتی',
        'profile_preview' => 'پێشبینی پڕۆفایل',
        'shop_snapshot' => 'وێنەی گشتی دوکان',
        'shop_snapshot_desc' => 'ئەمە شێوازی بەرزکردنەوەی دوکانەکەتە بۆ کڕیارەکان لە ڕێۆنیک.',
        'uncategorized' => 'بێ هاوپۆل',
        'add_products_feed' => 'هێشتا بەرهەم نییە. بەرهەم زیاد بکە بۆ دروستکردنی لیستی دوکان.',
        'not_set' => 'هەنووکە دیار نەکراوە',
        'shop_name_label' => 'ناوی دوکان',
        'business_name_label' => 'ناوی کاروبار',
        'description_label' => 'وەسف',
        'website_label' => 'ماڵپەڕ',
        'address_label' => 'ناونیشان',
        'hours_label' => 'کات',
        'social_links_label' => 'پەیوەندی کۆمەڵایەتی',
        'improve_profile' => 'بڕۆ لە پێشەاندانی پڕۆفایلی دوکانت',
        'profile_theme' => 'شێوازی پڕۆفایل',
        'primary_color' => 'ڕەنگی سەرەکی',
        'secondary_color' => 'ڕەنگی لاوەکی',
        'logo_or_url' => 'یان URLی لۆگۆ',
        'cover_url' => 'URLی وێنەی مافەر',
        'shop_description' => 'وەسفکردنی دوکان',
        'phone_label' => 'تەلەفون',
        'custom_url' => 'URLی تایبەتی دوکان',
        'save_shop_profile' => 'پڕۆفایلی دوکان پاشەکەوت بکە',
        'share_profile' => 'پڕۆفایلەکەت هاوبەش بکە',
        'public_link' => 'بەستەری گشتی',
        'copy' => 'کۆپی',
        'copied' => 'کۆپی کرا',
        'download_qr' => 'QR دابگرە',
        'quick_shortcuts' => 'قەدبڕە خێراکان',
        'products_nav' => 'بەرهەمەکان',
        'categories_nav' => 'هاوپۆلەکان',
        'analytics_nav' => 'ئامار',
        'settings_nav' => 'ڕێکخستن',
        'orders_nav' => 'داواکاریەکان',
        'public_profile' => 'پڕۆفایلی گشتی',
        'preview_below' => 'پێشبینی پڕۆفایل لەژێر',
        'brand_color_hint' => 'وەشانێکی ڕەنگی برند لەگەڵ شێوازی ئێستایت.',
        'color_change_hint' => 'گۆڕینی ڕەنگە سەرەوەی پێشبینیەکە نوێ دەکات.',
        'refresh_dashboard' => 'نوێکردنەوە',
        'preview_public_shop' => 'پێشبینی دوکانە گشتی',
        'total_visitors' => 'کۆی سەردانیەکان',
        'product_views_label' => 'بینینی بەرهەم',
        'daily_visitors' => 'سەردانەکانی ڕۆژانە',
        'monthly_visitors' => 'سەردانەکانی مانگانە',
        'top_viewed' => 'پەڕەکانی باشترین بینراو',
        'no_product_views' => 'هێشتا هیچ بینینی بەرهەمێک نییە.',
        'views_count' => '%d بینین',
        'popular_categories_analytics' => 'هاوپۆلە بەناوبانگەکان',
        'no_category_activity' => 'هێشتا هیچ چالاکییەکی هاوپۆل نییە.',
        'device_types' => 'جۆری ئامێر',
        'no_device_data' => 'هێشتا هیچ داتای ئامێر نییە.',
        'visits_count' => '%d سەردان',
        'visitor_locations' => 'شوێنی سەردانکەر',
        'no_location_data' => 'هێشتا هیچ داتای شوێن نییە.',
        'unknown' => 'نەناسراو',
        'sales_overview' => 'سەرپەرشتی فرۆشتن',
        'lifetime_revenue' => 'کۆی داهات',
        'sales_records' => 'تۆمارەکانی فرۆشتن',
        'units_sold' => 'دانەی فرۆشراو',
        'this_month' => 'ئەم مانگە',
        'from_date' => 'لە',
        'to_date' => 'تا',
        'sales_search' => 'گەڕان لە فرۆشتن',
        'sales_search_ph' => 'ناوی بەرهەم، SKU، تێبینی',
        'filter' => 'فیلتر کردن',
        'today' => 'ئەمڕۆ',
        'current_week' => 'ئەم هەفتەیە',
        'current_month' => 'ئەم مانگە',
        'current_year' => 'ئەم ساڵە',
        'vs_yesterday' => 'بەراورد بە دوێنێ',
        'vs_last_week' => 'بەراورد بە هەفتەی ڕابردوو',
        'vs_last_month' => 'بەراورد بە مانگی ڕابردوو',
        'vs_last_year' => 'بەراورد بە ساڵی ڕابردوو',
        'no_prior_data' => 'زانیاری پێشوو نییە',
        'best_selling' => 'باشترین بەرهەمە فرۆشراوەکان',
        'no_sales_yet' => 'هێشتا هیچ فرۆشتنێک تۆمار نەکراوە.',
        'pcs' => 'دانە',
        'category_revenue' => 'داهاتی هاوپۆل',
        'no_category_revenue' => 'هێشتا داهاتی هاوپۆل نییە.',
        'revenue_30_days' => 'داهات (٣٠ ڕۆژی ڕابردوو)',
        'revenue_monthly' => 'داهات (مانگانە)',
        'record_sale' => 'تۆمارکردنی فرۆشتن',
        'product_select' => 'بەرهەم',
        'general_item' => 'ئایتمی گشتی',
        'quantity' => 'ژمارە',
        'unit_price' => 'نرخی یەکە (IQD)',
        'sale_date' => 'ڕۆژی فرۆشتن',
        'notes' => 'تێبینی',
        'notes_ph' => 'تێبینی هەڵبژێردراو',
        'record_sale_btn' => 'فرۆشتن تۆمار بکە',
        'recent_sales' => 'فرۆشتنە نوێیەکان',
        'no_sales_period' => 'هیچ فرۆشتنێک بۆ ئەم ماوەیە نەدۆزرایەوە.',
        'no_category' => 'بێ هاوپۆل',
        'qty_label' => 'ژمارە',
        'notes_label' => 'تێبینی',
        'business_management' => 'کارگێڕی کاروبار',
        'store_health' => 'تەندروستی دوکان',
        'store_health_desc' => 'ئەم داشبۆردە یارمەتیت دەدات پڕۆفایلی دوکانت، مەخزانت و پەیوەندیدانی کڕیارەکان بەڕێوببەیت.',
        'recent_activity' => 'چالاکی نوێ',
        'recent_activity_desc' => 'نوێکردنەوەی لیست، بینینی بەرهەم، و پەیوەندی نوێ لێرەدا بگەرێنەوە.',
        'edit_product' => 'دەستکاری بەرهەم',
        'subcategory' => 'ژێرهاوپۆل',
        'subcategory_ph' => 'هاوپۆلی هەلبژێردراو',
        'brand_ph' => 'مارکە',
        'featured' => 'تایبەت',
        'tags_ph' => 'فڕۆشتن، نوێ، تایبەتکراو',
        'update_product' => 'نوێکردنەوەی بەرهەم',
        'delete_product' => 'سڕینەوە',
        'edit' => 'دەستکاری',
        'featured_badge' => 'تایبەت کراو',
        'store_profile_setup' => 'ڕێکخستنی پڕۆفایلی دوکان',
        'logo_image' => 'وێنەی لۆگۆ',
        'save_profile' => 'پڕۆفایل پاشەکەوت بکە',
        'notifications_comm' => 'ئاگادارکردنەوە و پەیوەندیدان',
        'inquiry_name_ph' => 'ناوی تۆ',
        'inquiry_email_ph' => 'ئیمەیڵ',
        'inquiry_phone_ph' => 'تەلەفون',
        'inquiry_message_ph' => 'چۆن دەتوانین یارمەتیت بدەین؟',
        'send_inquiry' => 'ناردنی پرسیار',
        'call' => 'پەیوەندی',
        'email_label' => 'ئیمەیڵ',
        'recent_inquiries' => 'پرسیارە نوێیەکان',
        'no_inquiries' => 'هێشتا هیچ پرسیارێک نییە.',
        'customer' => 'کڕیار',
        'communication_history' => 'مێژووی پەیوەندیدان',
        'comm_history_hint' => 'پرسیارە نوێیەکان، داواکارییەکان و نوێکردنەوەکانی دوکان لێرە ببینە.',
        'role_seller' => 'فرۆشیار',
        'role_customer' => 'کڕیار',
        'role_admin' => 'ئەدمین',
        'stock_in_stock' => 'بەردەستە',
        'stock_out_of_stock' => 'بەردەست نییە',
        'stock_low_stock' => 'کەمە لە مەخزەن',
        'product_deleted' => 'بەرهەم سڕایەوە.',
        'product_updated' => 'بەرهەم نوێکرایەوە.',
        'sale_recorded' => 'فرۆشتن بە سەرکەوتوویی تۆمار کرا.',
        'sale_invalid' => 'تکایە نرخ و ڕۆژی فرۆشتنێکی دروست بنووسە.',
        'sale_deleted' => 'فرۆشتن سڕایەوە.',
        'image_upload_failed' => 'بارکردنی وێنە سەرکەوتوو نەبوو.',
        'image_too_large' => 'تکایە وێنەیەک کەمتر لە ٢MB بار بکە.',
        'inquiry_received' => 'پرسیارەکەت وەرگیرا. بەم زووانە پەیوەندیت پێوە دەکەین.',
        'subscription_disabled' => 'کڕینی ئابوونە لەم داشبۆردەدا ناچالاکە.',
        'admin_deleted' => 'وورک‌اسپەیس و داتاکانی پەیوەندیدار سڕانەوە.',
        'chart_revenue' => 'داهات (IQD)',
        'product_num' => 'بەرهەم #%d',
        'stock_status' => 'دۆخی سټۆک',
        'stock_preorder' => 'پێش داواکاری',
        'tags' => 'تاگ',
        'main_image' => 'وێنەی سەرەکی',
        'image_url_or' => 'یان URLی وێنە',
        'gallery_images' => 'چندین وێنە',
        'save_changes' => 'پاشکەوتکردنی گۆڕانکاری',
        'cancel' => 'ڕەتکردنەوە',
    ],
    'ar' => [
        'site_title' => 'ريونيك — السوق المحلي',
        'site_subtitle' => 'سوق محلي',
        'search_placeholder' => 'ابحث عن الأعمال أو المنتجات',
        'search_label' => 'بحث',
        'search_by_name' => 'البحث بالاسم',
        'location_label' => 'الموقع',
        'my_shop' => 'متجري',
        'login' => 'تسجيل الدخول',
        'logout' => 'تسجيل الخروج',
        'products_count' => '%d منتج',
        'see_products' => 'عرض المنتجات',
        'contact' => 'تواصل',
        'seller_dashboard' => 'لوحة البائع',
        'workspace_id' => 'معرف مساحة العمل',
        'add_product' => 'إضافة منتج',
        'your_products' => 'منتجاتك',
        'no_products' => 'لا توجد منتجات بعد.',
        'product_added' => 'تمت إضافة المنتج.',
        'category' => 'الفئة',
        'category_placeholder' => 'اسم الفئة (جديدة أو موجودة)',
        'product_name' => 'اسم المنتج',
        'price' => 'السعر (IQD)',
        'image_url' => 'رابط الصورة',
        'description' => 'الوصف',
        'add_button' => 'إضافة',
        'login_title' => 'تسجيل الدخول',
        'close' => 'إغلاق',
        'customer_quick' => 'عميل (سريع)',
        'customer_name' => 'الاسم',
        'customer_email' => 'البريد الإلكتروني',
        'customer_button' => 'متابعة كعميل',
        'seller' => 'بائع',
        'seller_password' => 'كلمة المرور',
        'seller_button' => 'تسجيل الدخول كبائع',
        'seller_helper' => 'يمكن للمسؤول فقط إنشاء حسابات البائعين والموافقة عليها؛ اطلب من المسؤول إضافة حسابك والموافقة عليه.',
        'invalid_seller' => 'بيانات تسجيل البائع غير صالحة (نموذج أولي).',
        'footer' => 'ريونيك — نموذج سوق محلي',
        'language' => 'اللغة',
        'theme_toggle' => 'تبديل الثيم',
        'hero_title' => 'اكتشف المتاجر المحلية الموثوقة',
        'hero_subtitle' => 'تصفح المتاجر المحلية، واعثر على المنتجات المميزة، وتواصل مع البائعين بسهولة في تجربة سوق واحدة أنيقة.',
        'hero_cta' => 'استكشف الآن',
        'hero_secondary' => 'اصبح بائعًا',
        'featured_stores' => 'المتاجر المميزة',
        'featured_subtitle' => 'قائمة مختارة من الأعمال المحلية جاهزة لإبهارك.',
        'clear_search' => 'مسح البحث',
        'empty_title' => 'لم يتم العثور على متاجر تطابق بحثك',
        'empty_subtitle' => 'جرّب كلمة أخرى أو تصفح الفئات المميزة أعلاه.',
        'categories_title' => 'الفئات الشهيرة',
        'category_fashion' => 'الأزياء',
        'category_electronics' => 'الإلكترونيات',
        'category_food' => 'الطعام',
        'category_beauty' => 'الجمال',
        'location_sulaimani' => 'السليمانية',
        'location_erbil' => 'أربيل',
        'stats_shops' => 'المتاجر المحلية',
        'stats_products' => 'المنتجات المدرجة',
        'stats_fast' => 'تواصل سريع',
        'payment_title' => 'ادفع عبر FIB أو FastPay',
        'payment_methods' => 'خيارات الدفع',
        'pay_with_fib' => 'الدفع عبر FIB',
        'pay_with_fastpay' => 'الدفع عبر FastPay',
        'payment_note' => 'اختر وسيلة الدفع ثم أكد الطلب عبر واتساب.',
        'admin' => 'المشرف',
        'light' => 'فاتح',
        'dark' => 'داكن',
        'hero_badge' => 'لا حاجة لحساب • تصفح المتاجر وتواصل مع البائعين بسرعة',
        'admin_dashboard' => 'لوحة المشرف',
        'admin_subtitle' => 'ملخص المنصة وإدارة مساحات العمل.',
        'refresh' => 'تحديث',
        'public_view' => 'عرض عام',
        'stat_workspaces' => 'مساحات العمل',
        'stat_products' => 'المنتجات',
        'stat_sales' => 'المبيعات',
        'stat_revenue' => 'الإيرادات',
        'search_workspaces' => 'البحث في مساحات العمل',
        'search_btn' => 'بحث',
        'table_slug' => 'المعرّف',
        'table_name' => 'الاسم',
        'table_actions' => 'الإجراءات',
        'no_workspaces' => 'لم يتم العثور على مساحات عمل.',
        'view' => 'عرض',
        'delete' => 'حذف',
        'delete_workspace_confirm' => 'حذف مساحة العمل وجميع البيانات المرتبطة؟',
        'brand_label' => 'العلامة',
        'qr_code' => 'رمز QR',
        'qr_print_ready' => 'QR جاهز للطباعة للمتجر',
        'store_categories' => 'الفئات',
        'general' => 'عام',
        'search_products' => 'البحث في المنتجات',
        'all_categories' => 'جميع الفئات',
        'all_subcategories' => 'جميع الفئات الفرعية',
        'all_brands' => 'جميع العلامات',
        'all_tags' => 'جميع الوسوم',
        'sort_newest' => 'الأحدث',
        'sort_price_asc' => 'السعر: من الأقل للأعلى',
        'sort_price_desc' => 'السعر: من الأعلى للأقل',
        'sort_oldest' => 'الأقدم',
        'apply_filters' => 'تطبيق الفلاتر',
        'reset' => 'إعادة تعيين',
        'contact_social' => 'التواصل والاجتماعي',
        'no_social' => 'لا توجد روابط اجتماعية بعد.',
        'visit_website' => 'زيارة الموقع',
        'shop_profile' => 'ملف المتجر',
        'default_shop_bio' => 'هذا المتجر لديه ملف Reyonic سريع للمنتجات والطلبات.',
        'location_map' => 'خريطة الموقع',
        'open_maps' => 'اضغط للفتح في Google Maps.',
        'quick_actions' => 'إجراءات سريعة',
        'browse' => 'تصفح',
        'share_btn' => 'مشاركة',
        'copy_link' => 'نسخ الرابط',
        'contact_store' => 'تواصل مع المتجر',
        'contact_store_title' => 'تواصل مع هذا المتجر',
        'contact_store_desc' => 'هذه الصفحة لتصفح ملفات المتاجر ومحافظ المنتجات. تواصل مع المتجر للتوفر أو التفاصيل.',
        'no_products_store' => 'هذا المتجر لا يحتوي على منتجات بعد.',
        'view_details' => 'عرض التفاصيل',
        'no_image' => 'لا توجد صورة',
        'product_details' => 'تفاصيل المنتج',
        'back_to_store' => 'العودة للمتجر',
        'sku_label' => 'SKU',
        'na' => 'غ/م',
        'availability' => 'التوفر',
        'share_product' => 'مشاركة المنتج',
        'share_whatsapp' => 'مشاركة عبر واتساب',
        'product_link' => 'رابط المنتج',
        'cover_preview' => 'معاينة صورة الغلاف',
        'shop_desc_preview' => 'معاينة وصف متجرك تظهر هنا.',
        'social_label' => 'اجتماعي',
        'profile_preview' => 'معاينة الملف',
        'shop_snapshot' => 'لمحة عن المتجر',
        'shop_snapshot_desc' => 'هكذا يظهر متجرك للعملاء على Reyonic.',
        'uncategorized' => 'بدون فئة',
        'add_products_feed' => 'لا توجد منتجات بعد. أضف منتجات لبناء قائمة متجرك.',
        'not_set' => 'غير محدد بعد',
        'shop_name_label' => 'اسم المتجر',
        'business_name_label' => 'اسم العمل',
        'description_label' => 'الوصف',
        'website_label' => 'الموقع',
        'address_label' => 'العنوان',
        'hours_label' => 'الساعات',
        'social_links_label' => 'روابط اجتماعية',
        'improve_profile' => 'حسّن عرض ملف متجرك',
        'profile_theme' => 'سمة الملف',
        'primary_color' => 'اللون الأساسي',
        'secondary_color' => 'اللون الثانوي',
        'logo_or_url' => 'أو رابط الشعار',
        'cover_url' => 'رابط صورة الغلاف',
        'shop_description' => 'وصف المتجر',
        'phone_label' => 'الهاتف',
        'custom_url' => 'رابط المتجر المخصص',
        'save_shop_profile' => 'حفظ ملف المتجر',
        'share_profile' => 'شارك ملفك',
        'public_link' => 'الرابط العام',
        'copy' => 'نسخ',
        'copied' => 'تم النسخ',
        'download_qr' => 'تنزيل QR',
        'quick_shortcuts' => 'اختصارات سريعة',
        'products_nav' => 'المنتجات',
        'categories_nav' => 'الفئات',
        'analytics_nav' => 'التحليلات',
        'settings_nav' => 'الإعدادات',
        'orders_nav' => 'الطلبات',
        'public_profile' => 'الملف العام',
        'preview_below' => 'معاينة الملف أدناه',
        'brand_color_hint' => 'نسخة بلون العلامة التجارية مع سمتك الحالية.',
        'color_change_hint' => 'تغيير اللون العلوي يحدّث المعاينة.',
        'refresh_dashboard' => 'تحديث',
        'preview_public_shop' => 'معاينة المتجر العام',
        'total_visitors' => 'إجمالي الزيارات',
        'product_views_label' => 'مشاهدات المنتج',
        'daily_visitors' => 'زيارات يومية',
        'monthly_visitors' => 'زيارات شهرية',
        'top_viewed' => 'الصفحات الأكثر مشاهدة',
        'no_product_views' => 'لا توجد مشاهدات منتج بعد.',
        'views_count' => '%d مشاهدة',
        'popular_categories_analytics' => 'الفئات الشائعة',
        'no_category_activity' => 'لا يوجد نشاط فئات بعد.',
        'device_types' => 'أنواع الأجهزة',
        'no_device_data' => 'لا توجد بيانات أجهزة بعد.',
        'visits_count' => '%d زيارة',
        'visitor_locations' => 'مواقع الزوار',
        'no_location_data' => 'لا توجد بيانات موقع بعد.',
        'unknown' => 'غير معروف',
        'sales_overview' => 'نظرة عامة على المبيعات',
        'lifetime_revenue' => 'إجمالي الإيرادات',
        'sales_records' => 'سجلات المبيعات',
        'units_sold' => 'الوحدات المباعة',
        'this_month' => 'هذا الشهر',
        'from_date' => 'من',
        'to_date' => 'إلى',
        'sales_search' => 'البحث في المبيعات',
        'sales_search_ph' => 'اسم المنتج، SKU، ملاحظات',
        'filter' => 'تصفية',
        'today' => 'اليوم',
        'current_week' => 'الأسبوع الحالي',
        'current_month' => 'الشهر الحالي',
        'current_year' => 'السنة الحالية',
        'vs_yesterday' => 'مقارنة بالأمس',
        'vs_last_week' => 'مقارنة بالأسبوع الماضي',
        'vs_last_month' => 'مقارنة بالشهر الماضي',
        'vs_last_year' => 'مقارنة بالسنة الماضية',
        'no_prior_data' => 'لا توجد بيانات سابقة',
        'best_selling' => 'المنتجات الأكثر مبيعاً',
        'no_sales_yet' => 'لم تُسجّل مبيعات بعد.',
        'pcs' => 'قطعة',
        'category_revenue' => 'إيرادات الفئة',
        'no_category_revenue' => 'لا توجد إيرادات فئة بعد.',
        'revenue_30_days' => 'الإيرادات (آخر 30 يوم)',
        'revenue_monthly' => 'الإيرادات (شهري)',
        'record_sale' => 'تسجيل عملية بيع',
        'product_select' => 'المنتج',
        'general_item' => 'عنصر عام',
        'quantity' => 'الكمية',
        'unit_price' => 'سعر الوحدة (IQD)',
        'sale_date' => 'تاريخ البيع',
        'notes' => 'ملاحظات',
        'notes_ph' => 'ملاحظات اختيارية',
        'record_sale_btn' => 'تسجيل البيع',
        'recent_sales' => 'المبيعات الأخيرة',
        'no_sales_period' => 'لم يتم العثور على مبيعات لهذه الفترة.',
        'no_category' => 'بدون فئة',
        'qty_label' => 'الكمية',
        'notes_label' => 'ملاحظات',
        'business_management' => 'إدارة الأعمال',
        'store_health' => 'صحة المتجر',
        'store_health_desc' => 'تساعدك هذه اللوحة في إدارة ملف متجرك ومخزونك وتواصل العملاء.',
        'recent_activity' => 'النشاط الأخير',
        'recent_activity_desc' => 'تصفح القوائم ومشاهدات المنتجات ونشاط التواصل الجديد هنا.',
        'edit_product' => 'تعديل المنتج',
        'subcategory' => 'فئة فرعية',
        'subcategory_ph' => 'فئة فرعية اختيارية',
        'brand_ph' => 'العلامة',
        'featured' => 'مميز',
        'tags_ph' => 'تخفيض، جديد، مميز',
        'update_product' => 'تحديث المنتج',
        'delete_product' => 'حذف',
        'edit' => 'تعديل',
        'featured_badge' => 'مميز',
        'store_profile_setup' => 'إعداد ملف المتجر',
        'logo_image' => 'صورة الشعار',
        'save_profile' => 'حفظ الملف',
        'notifications_comm' => 'الإشعارات والتواصل',
        'inquiry_name_ph' => 'اسمك',
        'inquiry_email_ph' => 'البريد الإلكتروني',
        'inquiry_phone_ph' => 'الهاتف',
        'inquiry_message_ph' => 'كيف يمكننا مساعدتك؟',
        'send_inquiry' => 'إرسال استفسار',
        'call' => 'اتصال',
        'email_label' => 'البريد',
        'recent_inquiries' => 'الاستفسارات الأخيرة',
        'no_inquiries' => 'لا توجد استفسارات بعد.',
        'customer' => 'عميل',
        'communication_history' => 'سجل التواصل',
        'comm_history_hint' => 'راجع الاستفسارات والطلبات وتحديثات المتجر هنا.',
        'role_seller' => 'بائع',
        'role_customer' => 'عميل',
        'role_admin' => 'مشرف',
        'stock_in_stock' => 'متوفر',
        'stock_out_of_stock' => 'غير متوفر',
        'stock_low_stock' => 'مخزون منخفض',
        'product_deleted' => 'تم حذف المنتج.',
        'product_updated' => 'تم تحديث المنتج.',
        'sale_recorded' => 'تم تسجيل البيع بنجاح.',
        'sale_invalid' => 'يرجى إدخال سعر وتاريخ بيع صالحين.',
        'sale_deleted' => 'تم حذف البيع.',
        'image_upload_failed' => 'فشل رفع الصورة.',
        'image_too_large' => 'يرجى رفع صورة أصغر من 2MB.',
        'inquiry_received' => 'تم استلام استفسارك. سنتواصل معك قريباً.',
        'subscription_disabled' => 'مشتريات الاشتراك معطلة في لوحة الأعمال هذه.',
        'admin_deleted' => 'تم حذف مساحة العمل والبيانات المرتبطة.',
        'chart_revenue' => 'الإيرادات (IQD)',
        'product_num' => 'منتج #%d',
        'stock_status' => 'حالة المخزون',
        'stock_preorder' => 'طلب مسبق',
        'tags' => 'الوسوم',
        'main_image' => 'الصورة الرئيسية',
        'image_url_or' => 'أو رابط الصورة',
        'gallery_images' => 'صور متعددة',
        'save_changes' => 'حفظ التغييرات',
        'cancel' => 'إلغاء',
    ],
];

function translate($key, $lang, $translations) {
    return $translations[$lang][$key] ?? $translations['en'][$key] ?? $key;
}

function translateRole(string $role, string $lang, array $translations): string {
    $map = ['seller' => 'role_seller', 'customer' => 'role_customer', 'admin' => 'role_admin'];
    return translate($map[$role] ?? $role, $lang, $translations);
}

function translateStockStatus(string $status, string $lang, array $translations): string {
    $map = [
        'in_stock' => 'stock_in_stock',
        'out_of_stock' => 'stock_out_of_stock',
        'low_stock' => 'stock_low_stock',
        'preorder' => 'stock_preorder',
    ];
    $key = $map[strtolower($status)] ?? null;
    return $key ? translate($key, $lang, $translations) : ucwords(str_replace('_', ' ', $status));
}

function translateMessage(string $message, string $lang, array $translations): string {
    $map = [
        'Product added.' => 'product_added',
        'Product deleted.' => 'product_deleted',
        'Product updated.' => 'product_updated',
        'Sale recorded successfully.' => 'sale_recorded',
        'Please enter a valid unit price and sale date.' => 'sale_invalid',
        'Sale deleted.' => 'sale_deleted',
        'Image upload failed.' => 'image_upload_failed',
        'Please upload an image smaller than 2MB.' => 'image_too_large',
        'Inquiry received. We will contact you soon.' => 'inquiry_received',
        'Subscription purchases are disabled in this business dashboard.' => 'subscription_disabled',
        'Workspace and related data deleted.' => 'admin_deleted',
    ];
    $key = $map[$message] ?? null;
    return $key ? translate($key, $lang, $translations) : $message;
}

function ensureSellerSubscription(PDO $pdo, int $userId, int $workspaceId): array {
    $stmt = $pdo->prepare("SELECT * FROM subscriptions WHERE user_id = ? LIMIT 1");
    $stmt->execute([$userId]);
    $existing = $stmt->fetch();
    if ($existing) {
        $update = $pdo->prepare("UPDATE users SET subscription_status = ?, subscription_plan = ?, subscription_expires_at = ?, subscription_renewal_at = ?, subscription_started_at = ?, subscription_price = ?, subscription_currency = ? WHERE id = ?");
        $update->execute([
            $existing['status'] ?? 'trial_active',
            $existing['plan_key'] ?? 'trial',
            $existing['expires_at'],
            $existing['renews_at'],
            $existing['started_at'],
            $existing['price'] ?? 0,
            $existing['currency'] ?? 'IQD',
            $userId,
        ]);
        return $existing;
    }

    $trialExpires = date('Y-m-d H:i:s', strtotime('+14 days'));
    $insert = $pdo->prepare("INSERT INTO subscriptions (workspace_id, user_id, plan_key, plan_name, status, trial_used, price, currency, started_at, expires_at, renews_at, created_at) VALUES (?, ?, ?, ?, ?, 1, 0, 'IQD', NOW(), ?, ?, NOW())");
    $insert->execute([$workspaceId, $userId, 'trial', 'Free trial', 'trial_active', $trialExpires, $trialExpires]);

    $update = $pdo->prepare("UPDATE users SET subscription_status = ?, subscription_plan = ?, subscription_expires_at = ?, subscription_renewal_at = ?, subscription_started_at = ?, subscription_price = ?, subscription_currency = ? WHERE id = ?");
    $update->execute(['trial_active', 'trial', $trialExpires, $trialExpires, date('Y-m-d H:i:s'), 0, 'IQD', $userId]);

    return ['plan_key' => 'trial', 'plan_name' => 'Free trial', 'status' => 'trial_active', 'expires_at' => $trialExpires, 'renews_at' => $trialExpires, 'price' => '0'];
}

function getSellerSubscription(PDO $pdo, int $userId): array {
    $stmt = $pdo->prepare("SELECT * FROM subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1");
    $stmt->execute([$userId]);
    $row = $stmt->fetch();
    return $row ?: [];
}

function trackEvent(PDO $pdo, int $workspaceId, string $eventType, ?int $productId = null, ?string $deviceType = null, ?string $city = null, ?string $country = null): void {
    $insert = $pdo->prepare("INSERT INTO analytics_events (workspace_id, event_type, product_id, device_type, city, country, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
    $insert->execute([$workspaceId, $eventType, $productId, $deviceType, $city, $country]);
}

function analyticsSummary(PDO $pdo, int $workspaceId): array {
    $totals = $pdo->prepare("SELECT COUNT(*) AS total_visitors FROM analytics_events WHERE workspace_id = ? AND event_type = 'visit'");
    $totals->execute([$workspaceId]);
    $totalVisitors = intval($totals->fetchColumn() ?: 0);

    $productViews = $pdo->prepare("SELECT COUNT(*) AS total FROM analytics_events WHERE workspace_id = ? AND event_type = 'product_view'");
    $productViews->execute([$workspaceId]);
    $productViewCount = intval($productViews->fetchColumn() ?: 0);

    $topProducts = $pdo->prepare("SELECT product_id, COUNT(*) AS views FROM analytics_events WHERE workspace_id = ? AND event_type = 'product_view' AND product_id IS NOT NULL GROUP BY product_id ORDER BY views DESC LIMIT 5");
    $topProducts->execute([$workspaceId]);
    $topProductsRows = $topProducts->fetchAll();

    $daily = $pdo->prepare("SELECT COUNT(*) AS c FROM analytics_events WHERE workspace_id = ? AND event_type = 'visit' AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)");
    $daily->execute([$workspaceId]);
    $weekly = $pdo->prepare("SELECT COUNT(*) AS c FROM analytics_events WHERE workspace_id = ? AND event_type = 'visit' AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)");
    $weekly->execute([$workspaceId]);
    $monthly = $pdo->prepare("SELECT COUNT(*) AS c FROM analytics_events WHERE workspace_id = ? AND event_type = 'visit' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)");
    $monthly->execute([$workspaceId]);

    $devices = $pdo->prepare("SELECT device_type, COUNT(*) AS c FROM analytics_events WHERE workspace_id = ? AND device_type IS NOT NULL GROUP BY device_type ORDER BY c DESC LIMIT 5");
    $devices->execute([$workspaceId]);
    $deviceRows = $devices->fetchAll();

    $locations = $pdo->prepare("SELECT city, country, COUNT(*) AS c FROM analytics_events WHERE workspace_id = ? AND city IS NOT NULL GROUP BY city, country ORDER BY c DESC LIMIT 8");
    $locations->execute([$workspaceId]);
    $locationRows = $locations->fetchAll();

    $categories = $pdo->prepare("SELECT c.name AS category_name, COUNT(*) AS c FROM analytics_events a LEFT JOIN products p ON a.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id WHERE a.workspace_id = ? AND a.event_type = 'product_view' AND c.name IS NOT NULL GROUP BY c.name ORDER BY c DESC LIMIT 6");
    $categories->execute([$workspaceId]);
    $categoryRows = $categories->fetchAll();

    return [
        'total_visitors' => $totalVisitors,
        'product_views' => $productViewCount,
        'top_products' => $topProductsRows,
        'daily_visitors' => intval($daily->fetchColumn() ?: 0),
        'weekly_visitors' => intval($weekly->fetchColumn() ?: 0),
        'monthly_visitors' => intval($monthly->fetchColumn() ?: 0),
        'devices' => $deviceRows,
        'locations' => $locationRows,
        'categories' => $categoryRows,
    ];
}

function salesSummary(PDO $pdo, int $workspaceId, ?string $fromDate = null, ?string $toDate = null, ?string $query = null): array {
    $sqlFrom = "sales s LEFT JOIN products p ON s.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id";
    $where = "WHERE s.workspace_id = ?";
    $params = [$workspaceId];

    if ($fromDate !== null && $fromDate !== '') {
        $where .= " AND s.sale_date >= ?";
        $params[] = $fromDate;
    }
    if ($toDate !== null && $toDate !== '') {
        $where .= " AND s.sale_date <= ?";
        $params[] = $toDate;
    }
    if ($query !== null && $query !== '') {
        $where .= " AND (s.notes LIKE ? OR p.name LIKE ? OR p.sku LIKE ? OR c.name LIKE ?)";
        $like = '%' . $query . '%';
        $params[] = $like;
        $params[] = $like;
        $params[] = $like;
        $params[] = $like;
    }

    $summarySql = "SELECT COUNT(*) AS orders, COALESCE(SUM(s.quantity),0) AS units, COALESCE(SUM(s.total_price),0) AS revenue FROM sales s LEFT JOIN products p ON s.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id $where";
    $summary = $pdo->prepare($summarySql);
    $summary->execute($params);
    $totals = $summary->fetch();

    $today = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND sale_date = CURDATE()");
    $today->execute([$workspaceId]);
    $week = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND YEARWEEK(sale_date, 1) = YEARWEEK(CURDATE(), 1)");
    $week->execute([$workspaceId]);
    $month = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND YEAR(sale_date) = YEAR(CURDATE()) AND MONTH(sale_date) = MONTH(CURDATE())");
    $month->execute([$workspaceId]);
    $year = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND YEAR(sale_date) = YEAR(CURDATE())");
    $year->execute([$workspaceId]);

    // Previous-period comparisons, so the seller can see growth (not just current totals)
    $yesterday = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND sale_date = DATE_SUB(CURDATE(), INTERVAL 1 DAY)");
    $yesterday->execute([$workspaceId]);
    $prevWeek = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND YEARWEEK(sale_date, 1) = YEARWEEK(DATE_SUB(CURDATE(), INTERVAL 1 WEEK), 1)");
    $prevWeek->execute([$workspaceId]);
    $prevMonth = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND YEAR(sale_date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 MONTH)) AND MONTH(sale_date) = MONTH(DATE_SUB(CURDATE(), INTERVAL 1 MONTH))");
    $prevMonth->execute([$workspaceId]);
    $prevYear = $pdo->prepare("SELECT COALESCE(SUM(total_price),0) FROM sales WHERE workspace_id = ? AND YEAR(sale_date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))");
    $prevYear->execute([$workspaceId]);

    $todayRevenue = floatval($today->fetchColumn() ?: 0);
    $weekRevenue = floatval($week->fetchColumn() ?: 0);
    $monthRevenue = floatval($month->fetchColumn() ?: 0);
    $yearRevenue = floatval($year->fetchColumn() ?: 0);
    $yesterdayRevenue = floatval($yesterday->fetchColumn() ?: 0);
    $prevWeekRevenue = floatval($prevWeek->fetchColumn() ?: 0);
    $prevMonthRevenue = floatval($prevMonth->fetchColumn() ?: 0);
    $prevYearRevenue = floatval($prevYear->fetchColumn() ?: 0);

    $pctChange = function (float $current, float $previous): ?float {
        if ($previous <= 0) {
            return $current > 0 ? null : 0.0;
        }
        return (($current - $previous) / $previous) * 100;
    };

    $bestProductsSql = "SELECT COALESCE(p.name, 'Unspecified') AS product_name, p.sku, SUM(s.quantity) AS qty, SUM(s.total_price) AS revenue FROM sales s LEFT JOIN products p ON s.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id $where GROUP BY p.id, p.name, p.sku ORDER BY qty DESC, revenue DESC LIMIT 5";
    $bestProducts = $pdo->prepare($bestProductsSql);
    $bestProducts->execute($params);
    $bestProductsRows = $bestProducts->fetchAll();

    $categoryRevenueSql = "SELECT COALESCE(c.name, 'Uncategorized') AS category_name, SUM(s.total_price) AS revenue, SUM(s.quantity) AS units FROM sales s LEFT JOIN products p ON s.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id $where GROUP BY c.id, c.name ORDER BY revenue DESC LIMIT 6";
    $categoryRevenue = $pdo->prepare($categoryRevenueSql);
    $categoryRevenue->execute($params);
    $categoryRows = $categoryRevenue->fetchAll();

    // Series: daily revenue for last 30 days (or filtered range)
    $dailyParams = $params;
    $dailyWhere = $where . " AND s.sale_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)";
    $dailySql = "SELECT s.sale_date AS d, COALESCE(SUM(s.total_price),0) AS revenue, COALESCE(SUM(s.quantity),0) AS units FROM sales s LEFT JOIN products p ON s.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id $dailyWhere GROUP BY s.sale_date ORDER BY s.sale_date ASC";
    $dailyStmt = $pdo->prepare($dailySql);
    $dailyStmt->execute($dailyParams);
    $dailyRows = $dailyStmt->fetchAll();

    // Series: monthly revenue for last 12 months
    $monthlyParams = $params;
    $monthlySql = "SELECT DATE_FORMAT(s.sale_date, '%Y-%m-01') AS month_start, COALESCE(SUM(s.total_price),0) AS revenue, COALESCE(SUM(s.quantity),0) AS units FROM sales s LEFT JOIN products p ON s.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id $where GROUP BY YEAR(s.sale_date), MONTH(s.sale_date) ORDER BY YEAR(s.sale_date) ASC, MONTH(s.sale_date) ASC LIMIT 24";
    $monthlyStmt = $pdo->prepare($monthlySql);
    $monthlyStmt->execute($monthlyParams);
    $monthlyRows = $monthlyStmt->fetchAll();

    return [
        'orders' => intval($totals['orders'] ?? 0),
        'units' => intval($totals['units'] ?? 0),
        'revenue' => floatval($totals['revenue'] ?? 0),
        'today_revenue' => $todayRevenue,
        'week_revenue' => $weekRevenue,
        'month_revenue' => $monthRevenue,
        'year_revenue' => $yearRevenue,
        'yesterday_revenue' => $yesterdayRevenue,
        'prev_week_revenue' => $prevWeekRevenue,
        'prev_month_revenue' => $prevMonthRevenue,
        'prev_year_revenue' => $prevYearRevenue,
        'today_change' => $pctChange($todayRevenue, $yesterdayRevenue),
        'week_change' => $pctChange($weekRevenue, $prevWeekRevenue),
        'month_change' => $pctChange($monthRevenue, $prevMonthRevenue),
        'year_change' => $pctChange($yearRevenue, $prevYearRevenue),
        'best_products' => $bestProductsRows,
        'category_revenue' => $categoryRows,
      'daily_series' => $dailyRows,
      'monthly_series' => $monthlyRows,
    ];
}

function fetchSalesRecords(PDO $pdo, int $workspaceId, ?string $fromDate = null, ?string $toDate = null, ?string $query = null): array {
    $where = "WHERE s.workspace_id = ?";
    $params = [$workspaceId];
    if ($fromDate !== null && $fromDate !== '') {
        $where .= " AND s.sale_date >= ?";
        $params[] = $fromDate;
    }
    if ($toDate !== null && $toDate !== '') {
        $where .= " AND s.sale_date <= ?";
        $params[] = $toDate;
    }
    if ($query !== null && $query !== '') {
        $where .= " AND (s.notes LIKE ? OR p.name LIKE ? OR p.sku LIKE ? OR c.name LIKE ? )";
        $like = '%' . $query . '%';
        $params[] = $like;
        $params[] = $like;
        $params[] = $like;
        $params[] = $like;
    }

    $stmt = $pdo->prepare("SELECT s.*, p.name AS product_name, p.sku, c.name AS category_name FROM sales s LEFT JOIN products p ON s.product_id = p.id LEFT JOIN categories c ON p.category_id = c.id $where ORDER BY s.sale_date DESC, s.id DESC LIMIT 40");
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function makeInvoice(PDO $pdo, int $workspaceId, int $userId, string $planKey, string $planName, float $amount, string $paymentMethod, string $status, string $invoiceNumber): string {
    $dir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'invoices';
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $fileName = $invoiceNumber . '.html';
    $path = 'uploads/invoices/' . $fileName;
    $fullPath = $dir . DIRECTORY_SEPARATOR . $fileName;
    $html = '<!doctype html><html><head><meta charset="utf-8"><title>Invoice ' . htmlspecialchars($invoiceNumber) . '</title><style>body{font-family:Arial,sans-serif;padding:24px;color:#111;} .box{border:1px solid #ddd;padding:16px;border-radius:8px;} .muted{color:#666;}</style></head><body><div class="box"><h2>Reyonic Invoice</h2><p><strong>Invoice:</strong> ' . htmlspecialchars($invoiceNumber) . '</p><p><strong>Workspace:</strong> #' . (int) $workspaceId . '</p><p><strong>Plan:</strong> ' . htmlspecialchars($planName) . '</p><p><strong>Amount:</strong> ' . number_format($amount, 0) . ' IQD</p><p><strong>Payment method:</strong> ' . htmlspecialchars(ucfirst($paymentMethod)) . '</p><p><strong>Status:</strong> ' . htmlspecialchars($status) . '</p><p class="muted">Generated automatically by Reyonic MVP.</p></div></body></html>';
    file_put_contents($fullPath, $html);
    return $path;
}

function ensureCategoryForWorkspace(PDO $pdo, int $workspace_id, string $name, ?int $parent_id = null): int {
    $name = trim($name);
    if ($name === '') {
        $name = 'General';
    }
    if ($parent_id !== null && $parent_id > 0) {
        $stmt = $pdo->prepare("SELECT id FROM categories WHERE workspace_id = ? AND name = ? AND parent_id = ? LIMIT 1");
        $stmt->execute([$workspace_id, $name, $parent_id]);
    } else {
        $stmt = $pdo->prepare("SELECT id FROM categories WHERE workspace_id = ? AND name = ? AND (parent_id IS NULL OR parent_id = 0) LIMIT 1");
        $stmt->execute([$workspace_id, $name]);
    }
    $existing = $stmt->fetch();
    if ($existing) {
        return intval($existing['id']);
    }
    $ins = $pdo->prepare("INSERT INTO categories (workspace_id,name,parent_id,created_at) VALUES (?, ?, ?, NOW())");
    $ins->execute([$workspace_id, $name, $parent_id && $parent_id > 0 ? $parent_id : null]);
    return intval($pdo->lastInsertId());
}

function parseTags(string $tags): array {
    $parts = preg_split('/[\s,]+/', trim($tags));
    $result = [];
    if (!$parts) {
        return $result;
    }
    foreach ($parts as $part) {
        $clean = trim($part);
        if ($clean !== '') {
            $result[] = $clean;
        }
    }
    return $result;
}

function productMatchesFilters(array $product, string $search, string $selectedCategory, string $selectedSubcategory, string $selectedBrand, string $selectedTag): bool {
    $haystack = strtolower(trim((string) ($product['name'] ?? '') . ' ' . ($product['description'] ?? '') . ' ' . ($product['category_name'] ?? '') . ' ' . ($product['parent_category_name'] ?? '') . ' ' . ($product['brand'] ?? '') . ' ' . ($product['tags'] ?? '')));
    if ($search !== '' && stripos($haystack, strtolower($search)) === false) {
        return false;
    }
    if ($selectedCategory !== '' && strtolower((string) ($product['parent_category_name'] ?? '')) !== strtolower($selectedCategory) && strtolower((string) ($product['category_name'] ?? '')) !== strtolower($selectedCategory)) {
        return false;
    }
    if ($selectedSubcategory !== '' && strtolower((string) ($product['category_name'] ?? '')) !== strtolower($selectedSubcategory)) {
        return false;
    }
    if ($selectedBrand !== '' && strtolower((string) ($product['brand'] ?? '')) !== strtolower($selectedBrand)) {
        return false;
    }
    if ($selectedTag !== '') {
        $tagList = array_map('strtolower', parseTags((string) ($product['tags'] ?? '')));
        if (!in_array(strtolower($selectedTag), $tagList, true)) {
            return false;
        }
    }
    return true;
}

function sortProductsByMode(array $products, string $sortBy): array {
    $sorted = $products;
    usort($sorted, static function ($a, $b) use ($sortBy) {
        $mode = strtolower($sortBy);
        if ($mode === 'price_asc') {
            return floatval($a['price'] ?? 0) <=> floatval($b['price'] ?? 0);
        }
        if ($mode === 'price_desc') {
            return floatval($b['price'] ?? 0) <=> floatval($a['price'] ?? 0);
        }
        if ($mode === 'oldest') {
            return strtotime((string) ($a['created_at'] ?? '')) <=> strtotime((string) ($b['created_at'] ?? ''));
        }
        return strtotime((string) ($b['created_at'] ?? '')) <=> strtotime((string) ($a['created_at'] ?? ''));
    });
    return $sorted;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['seller_login']) && !isset($_POST['customer_login'])) {
        // بۆ ئەکشنە گرنگەکان داوای CSRF بکە (لۆگین دەتوانرێت لابدرێت چونکە سیشن هێشتا نییە)
        if (!csrfVerify()) { http_response_code(400); exit('Invalid request.'); }
    }
    // Admin login derives from a single configured account only.
    // Use the configured ADMIN_EMAIL value and strong password policy.

    // Customer login (simple)
    if (isset($_POST['customer_login'])) {
        $email = trim($_POST['cust_email'] ?? '');
        $name = trim($_POST['cust_name'] ?? 'Guest');
        // In prototype: create or fetch a customer record in users table with workspace_id = 0 (global customers)
        $stmt = $pdo->prepare("SELECT id,name,email FROM users WHERE email = ? AND workspace_id = 0 LIMIT 1");
        $stmt->execute([$email]);
        $u = $stmt->fetch();
      if (isLoginLocked($pdo, 'login:' . $email)) {
        $login_error = 'زۆر هەوڵت داوە، تکایە دوای ' . LOGIN_LOCKOUT_MINUTES . ' خولەک تاقی بکەرەوە';
    } else {
        if (!$u) {
                $ins = $pdo->prepare("INSERT INTO users (workspace_id,name,email,password,role,created_at) VALUES (0,?,?,?,?,NOW())");
                $ins->execute([$name, $email, '', 'customer']);
                $id = $pdo->lastInsertId();
            $u = ['id'=>$id,'name'=>$name,'email'=>$email];
        }

        recordLoginAttempt($pdo, 'login:' . $email, true);
        clearLoginAttempts($pdo, 'login:' . $email);

        $_SESSION['auth'] = ['type'=>'customer','id'=>intval($u['id']),'name'=>$u['name'],'role'=>'customer'];
        regenerateSessionOnLogin();
        header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
        exit;
    }
    }

    // Seller/Admin login (simple)
    if (isset($_POST['seller_login'])) {
        $email = strtolower(trim($_POST['seller_email'] ?? ''));
        $password = trim($_POST['seller_password'] ?? '');
        $sellerName = $email ? explode('@', $email)[0] : 'Seller';
        $isAdminAttempt = $email === strtolower(ADMIN_EMAIL);

        if (isLoginLocked($pdo, 'login:' . $email)) {
            $login_error = 'زۆر هەوڵت داوە، تکایە دوای ' . LOGIN_LOCKOUT_MINUTES . ' خولەک تاقی بکەرەوە';
        } else {

        $stmt = $pdo->prepare("SELECT id,workspace_id,name,email,store_name,password,role,seller_status FROM users WHERE LOWER(email) = ? LIMIT 1");
        $stmt->execute([$email]);
        $u = $stmt->fetch();

        if ($u) {
            if ($isAdminAttempt) {
                if (!verifyPassword($password, $u['password'])) {
                    recordLoginAttempt($pdo, 'login:' . $email, false);
                    $login_error = 'Invalid admin credentials.';
                } else {
                    if ($u['role'] !== 'admin') {
                        $pdo->prepare("UPDATE users SET role = 'admin' WHERE id = ?")->execute([$u['id']]);
                    }
                    ensureSingleAdmin($pdo);
                    recordLoginAttempt($pdo, 'login:' . $email, true);
                    clearLoginAttempts($pdo, 'login:' . $email);
                    $_SESSION['auth'] = ['type' => 'admin', 'id' => intval($u['id']), 'name' => $u['name'], 'role' => 'admin'];
                    regenerateSessionOnLogin();
                    header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
                    exit;
                }
            } else {
                if (!verifyPassword($password, $u['password'])) {
                    recordLoginAttempt($pdo, 'login:' . $email, false);
                    $login_error = "Invalid seller credentials (prototype).";
                } elseif ($u['role'] === 'seller' && strtolower($u['seller_status'] ?? '') !== 'approved') {
                    $login_error = 'Seller account pending admin approval.';
                } else {
                    $role = $u['role'] ?: ($u['workspace_id'] > 0 ? 'seller' : 'customer');
                    recordLoginAttempt($pdo, 'login:' . $email, true);
                    clearLoginAttempts($pdo, 'login:' . $email);
                    if ($role === 'seller') {
                        $_SESSION['auth'] = ['type' => 'seller', 'id' => intval($u['id']), 'name' => $u['name'], 'workspace_id' => intval($u['workspace_id']), 'role' => 'seller'];
                    } else {
                        $_SESSION['auth'] = ['type' => 'customer', 'id' => intval($u['id']), 'name' => $u['name'], 'role' => 'customer'];
                    }
                    regenerateSessionOnLogin();
                    header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
                    exit;
                }
            }
        } elseif ($isAdminAttempt) {
    $setupKey = trim($_POST['admin_setup_key'] ?? '');
    if (!hash_equals(ADMIN_SETUP_KEY, $setupKey)) {
        recordLoginAttempt($pdo, 'login:' . $email, false);
        $login_error = 'کلیلی دامەزراندنی ئەدمین هەڵەیە.';
    } elseif (!isStrongPassword($password)) {
        $login_error = 'Admin password must be at least 12 characters...';
    } else {
                $adminName = 'Reyonic Admin';
                $hashedPassword = hashPassword($password);
                $ins = $pdo->prepare("INSERT INTO users (workspace_id,name,email,password,role,created_at) VALUES (0,?,?,?,?,NOW())");
                $ins->execute([$adminName, $email, $hashedPassword, 'admin']);
                ensureSingleAdmin($pdo);
                $u = ['id' => intval($pdo->lastInsertId()), 'name' => $adminName, 'email' => $email];
                $_SESSION['auth'] = ['type' => 'admin', 'id' => intval($u['id']), 'name' => $u['name'], 'role' => 'admin'];
                regenerateSessionOnLogin();
                header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
                exit;
            }
        } else {
            recordLoginAttempt($pdo, 'login:' . $email, false);
            $login_error = 'Seller account does not exist. Ask the admin to create and approve your account before logging in.';
        }

        }
    }

    if (isset($_POST['customer_inquiry_submit']) && $auth && $auth['type'] === 'seller') {
        $w = intval($auth['workspace_id']);
        $name = trim($_POST['inquiry_name'] ?? '');
        $email = trim($_POST['inquiry_email'] ?? '');
        $phone = trim($_POST['inquiry_phone'] ?? '');
        $message = trim($_POST['inquiry_message'] ?? '');
        if ($message !== '') {
            $stmt = $pdo->prepare("INSERT INTO inquiries (workspace_id, customer_name, customer_email, customer_phone, message, status, created_at) VALUES (?, ?, ?, ?, ?, 'new', NOW())");
            $stmt->execute([$w, $name, $email, $phone, $message]);
            $subscription_message = 'Inquiry received. We will contact you soon.';
        }
    } elseif (isset($_POST['buy_subscription']) && $auth && $auth['type'] === 'seller') {
        $subscription_message = 'Subscription purchases are disabled in this business dashboard.';
    } elseif (isset($_POST['seller_delete_product']) && $auth && $auth['type'] === 'seller') {
        $w = intval($auth['workspace_id']);
        $productId = intval($_POST['product_id'] ?? 0);
        if ($productId > 0) {
            $del = $pdo->prepare("DELETE FROM products WHERE id = ? AND workspace_id = ?");
            $del->execute([$productId, $w]);
            $product_message = 'Product deleted.';
        }
    } elseif (isset($_POST['seller_update_product']) && $auth && $auth['type'] === 'seller') {
        $w = intval($auth['workspace_id']);
        $productId = intval($_POST['product_id'] ?? 0);
        $cat = trim($_POST['prod_category'] ?? '');
        $subcat = trim($_POST['prod_subcategory'] ?? '');
        $pname = trim($_POST['prod_name'] ?? '');
        $price = floatval($_POST['prod_price'] ?? 0);
        $desc = trim($_POST['prod_desc'] ?? '');
        $sku = trim($_POST['prod_sku'] ?? '');
        $stockStatus = trim($_POST['prod_stock_status'] ?? 'in_stock');
        $featured = !empty($_POST['prod_featured']) ? 1 : 0;
        $brand = trim($_POST['prod_brand'] ?? '');
        $tags = trim($_POST['prod_tags'] ?? '');
        $img = trim($_POST['prod_image'] ?? '');
        $galleryPaths = [];

        $existingProduct = productById($pdo, $w, $productId);
        if ($existingProduct) {
            $img = $existingProduct['image_url'] ?? $img;
            $galleryPaths = !empty($existingProduct['gallery_images']) ? json_decode($existingProduct['gallery_images'], true) ?: [] : [];
        }

        if (isset($_FILES['prod_image_file']) && is_array($_FILES['prod_image_file']) && $_FILES['prod_image_file']['error'] === UPLOAD_ERR_OK && is_uploaded_file($_FILES['prod_image_file']['tmp_name'])) {
            $file = $_FILES['prod_image_file'];
            $allowedExt = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
            $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (in_array($ext, $allowedExt, true) && $file['size'] > 0 && $file['size'] <= 2 * 1024 * 1024) {
                $targetDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'products';
                if (!is_dir($targetDir)) {
                    mkdir($targetDir, 0755, true);
                }
                $fileName = 'product_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
                $targetPath = $targetDir . DIRECTORY_SEPARATOR . $fileName;
                if (!isGenuineImageUpload($file['tmp_name'])) {
                    $product_message = 'ئەم فایلە وێنەیەکی ڕاستەقینە نییە.';
                } else {
                    lockDownUploadsFolder($targetDir);
                    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
                        $img = 'uploads/products/' . $fileName;
                    } else {
                        $product_message = 'Image upload failed.';
                    }
                }
            } else {
                $product_message = 'Please upload an image smaller than 2MB.';
            }
        }

        if (isset($_FILES['prod_images']) && is_array($_FILES['prod_images']['name'])) {
            $files = $_FILES['prod_images'];
            for ($i = 0; $i < count($files['name']); $i++) {
                if ($files['error'][$i] !== UPLOAD_ERR_OK) {
                    continue;
                }
                $name = $files['name'][$i];
                $tmp = $files['tmp_name'][$i];
                $allowedExt = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
                $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                if (!in_array($ext, $allowedExt, true) || $files['size'][$i] <= 0 || $files['size'][$i] > 2 * 1024 * 1024) {
                    continue;

                }
                $targetDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'products';
                if (!is_dir($targetDir)) {
                    mkdir($targetDir, 0755, true);
                }
                $fileName = 'gallery_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
                $targetPath = $targetDir . DIRECTORY_SEPARATOR . $fileName;
                if (!isGenuineImageUpload($tmp)) {
            $product_message = 'یەکێک لە فایلەکان وێنەی ڕاستەقینە نییە!';
        } else {
            lockDownUploadsFolder($targetDir);
            if (move_uploaded_file($tmp, $targetPath)) {
                $galleryPaths[] = './uploads/products/' . $fileName;
            }
        }
            }
        }

        $parentCatId = $cat !== '' ? ensureCategoryForWorkspace($pdo, $w, $cat) : 0;
        $cat_id = $subcat !== '' ? ensureCategoryForWorkspace($pdo, $w, $subcat, $parentCatId) : $parentCatId;

        $galleryJson = json_encode($galleryPaths, JSON_UNESCAPED_SLASHES);
        $upd = $pdo->prepare("UPDATE products SET category_id = ?, name = ?, price = ?, description = ?, image_url = ?, sku = ?, stock_status = ?, featured = ?, gallery_images = ?, brand = ?, tags = ?, updated_at = NOW() WHERE id = ? AND workspace_id = ?");
        $upd->execute([$cat_id, $pname, $price, $desc, $img, $sku, $stockStatus, $featured, $galleryJson, $brand, $tags, $productId, $w]);
        if (empty($product_message)) {
            $product_message = 'Product updated.';
        }
    } elseif (isset($_POST['seller_add_product']) && $auth && $auth['type'] === 'seller') {
        $w = intval($auth['workspace_id']);
        $cat = trim($_POST['prod_category'] ?? '');
        $subcat = trim($_POST['prod_subcategory'] ?? '');
        $pname = trim($_POST['prod_name'] ?? '');
        $price = floatval($_POST['prod_price'] ?? 0);
        $desc = trim($_POST['prod_desc'] ?? '');
        $sku = trim($_POST['prod_sku'] ?? '');
        $stockStatus = trim($_POST['prod_stock_status'] ?? 'in_stock');
        $featured = !empty($_POST['prod_featured']) ? 1 : 0;
        $brand = trim($_POST['prod_brand'] ?? '');
        $tags = trim($_POST['prod_tags'] ?? '');
        $img = trim($_POST['prod_image'] ?? '');
        $galleryPaths = [];

        if (isset($_FILES['prod_image_file']) && is_array($_FILES['prod_image_file']) && $_FILES['prod_image_file']['error'] === UPLOAD_ERR_OK && is_uploaded_file($_FILES['prod_image_file']['tmp_name'])) {
            $file = $_FILES['prod_image_file'];
            $allowedExt = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
            $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (in_array($ext, $allowedExt, true) && $file['size'] > 0 && $file['size'] <= 2 * 1024 * 1024) {
                $targetDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'products';
                if (!is_dir($targetDir)) {
                    mkdir($targetDir, 0755, true);
                }
                $fileName = 'product_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
                $targetPath = $targetDir . DIRECTORY_SEPARATOR . $fileName;
               if (!isGenuineImageUpload($file['tmp_name'])) {
            $product_message = 'ئەم فایلە وێنەیەکی ڕاستەقینە نییە!';
        } else {
            lockDownUploadsFolder($targetDir);
            if (move_uploaded_file($file['tmp_name'], $targetPath)) {
                $img = './uploads/products/' . $fileName;
            } else {
                $product_message = 'Image upload failed.';
            }
        }
            } else {
                $product_message = 'Please upload an image smaller than 2MB.';
            }
        }

        if (isset($_FILES['prod_images']) && is_array($_FILES['prod_images']['name'])) {
            $files = $_FILES['prod_images'];
            for ($i = 0; $i < count($files['name']); $i++) {
                if ($files['error'][$i] !== UPLOAD_ERR_OK) {
                    continue;
                }
                $name = $files['name'][$i];
                $tmp = $files['tmp_name'][$i];
                $allowedExt = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
                $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                if (!in_array($ext, $allowedExt, true) || $files['size'][$i] <= 0 || $files['size'][$i] > 2 * 1024 * 1024) {
                    continue;
                }
                $targetDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'products';
                if (!is_dir($targetDir)) {
                    mkdir($targetDir, 0755, true);
                }
                $fileName = 'gallery_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
                $targetPath = $targetDir . DIRECTORY_SEPARATOR . $fileName;
                if (!isGenuineImageUpload($tmp)) {
                    $product_message = 'یەکێک لە فایلەکان وێنەی ڕاستەقینە نییە!';
                } else {
                    lockDownUploadsFolder($targetDir);
                    if (move_uploaded_file($tmp, $targetPath)) {
                        $galleryPaths[] = 'uploads/products/' . $fileName;
                    }
                }
            }
        }

        $parentCatId = $cat !== '' ? ensureCategoryForWorkspace($pdo, $w, $cat) : 0;
        $cat_id = $subcat !== '' ? ensureCategoryForWorkspace($pdo, $w, $subcat, $parentCatId) : $parentCatId;
        $galleryJson = json_encode($galleryPaths, JSON_UNESCAPED_SLASHES);
        $ins = $pdo->prepare("INSERT INTO products (workspace_id,category_id,name,price,description,image_url,created_at,sku,stock_status,featured,gallery_images,brand,tags) VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?)");
        $ins->execute([$w, $cat_id, $pname, $price, $desc, $img, $sku, $stockStatus, $featured, $galleryJson, $brand, $tags]);
        if (empty($product_message)) {
            $product_message = "Product added.";
        }
    }

    if (isset($_POST['seller_update_profile']) && $auth && $auth['type'] === 'seller') {
        $w = intval($auth['workspace_id']);
        $storeName = trim($_POST['store_name'] ?? '');
        $businessName = trim($_POST['business_name'] ?? $storeName);
        $description = trim($_POST['store_description'] ?? '');
        $address = trim($_POST['store_address'] ?? '');
        $phone = trim($_POST['store_phone'] ?? '');
        $themeColor = trim($_POST['store_theme_color'] ?? '#0ea5a4');
        $hours = trim($_POST['store_hours'] ?? '');
        $social = trim($_POST['store_social'] ?? '');
        $cover = trim($_POST['store_cover'] ?? '');
        $customUrl = trim($_POST['store_url'] ?? '');
        $logo = trim($_POST['store_logo'] ?? '');

        if (isset($_FILES['store_logo_file']) && is_array($_FILES['store_logo_file']) && $_FILES['store_logo_file']['error'] === UPLOAD_ERR_OK && is_uploaded_file($_FILES['store_logo_file']['tmp_name'])) {
            $file = $_FILES['store_logo_file'];
            $allowedExt = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
            $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (in_array($ext, $allowedExt, true) && $file['size'] > 0 && $file['size'] <= 2 * 1024 * 1024) {
                $targetDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'logos';
                if (!is_dir($targetDir)) {
                    mkdir($targetDir, 0755, true);
                }
                $fileName = 'logo_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
                $targetPath = $targetDir . DIRECTORY_SEPARATOR . $fileName;
                if (!isGenuineImageUpload($file['tmp_name'])) {
            $product_message = 'لۆگۆکە وێنەیەکی ڕاستەقینە نییە!';
        } else {
            lockDownUploadsFolder($targetDir);
            if (move_uploaded_file($file['tmp_name'], $targetPath)) {
                $logo = './uploads/logos/' . $fileName;
            }
        }
            }
        }

        $website = trim($_POST['store_website'] ?? '');
        $slug = $customUrl !== '' ? strtolower(preg_replace('/[^a-z0-9]+/', '-', $customUrl)) : strtolower(preg_replace('/[^a-z0-9]+/', '-', $storeName));
        $primaryColor = trim($_POST['store_primary_color'] ?? $themeColor);
        $secondaryColor = trim($_POST['store_secondary_color'] ?? '#ffffff');
        $stmt = $pdo->prepare("UPDATE workspaces SET name = ?, store_name = ?, logo = ?, description = ?, address = ?, phone = ?, theme_color = ?, primary_color = ?, secondary_color = ?, business_hours = ?, social_links = ?, cover_image = ?, website = ?, slug = ? WHERE id = ?");
        $stmt->execute([$businessName, $storeName, $logo, $description, $address, $phone, $themeColor, $primaryColor, $secondaryColor, $hours, $social, $cover, $website, $slug, $w]);
        header("Location: ?my_shop=1&lang=" . urlencode($lang) . "&theme=" . urlencode($theme));
        exit;
    }

    if (isset($_POST['seller_add_sale']) && $auth && $auth['type'] === 'seller') {
        $w = intval($auth['workspace_id']);
        $productId = intval($_POST['sale_product_id'] ?? 0);
        $quantity = max(1, intval($_POST['sale_quantity'] ?? 1));
        $unitPrice = floatval($_POST['sale_unit_price'] ?? 0);
        $saleDate = trim($_POST['sale_date'] ?? date('Y-m-d'));
        $notes = trim($_POST['sale_notes'] ?? '');

        if ($unitPrice > 0 && preg_match('/^\d{4}-\d{2}-\d{2}$/', $saleDate)) {
            $totalPrice = $quantity * $unitPrice;
            $stmt = $pdo->prepare("INSERT INTO sales (workspace_id, product_id, quantity, unit_price, total_price, sale_date, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())");
            $stmt->execute([$w, $productId > 0 ? $productId : null, $quantity, $unitPrice, $totalPrice, $saleDate, $notes]);
            $sales_message = 'Sale recorded successfully.';
        } else {
            $sales_message = 'Please enter a valid unit price and sale date.';
        }
    }

    if (isset($_POST['seller_delete_sale']) && $auth && $auth['type'] === 'seller') {
        $w = intval($auth['workspace_id']);
        $saleId = intval($_POST['sale_id'] ?? 0);
        if ($saleId > 0) {
            $del = $pdo->prepare("DELETE FROM sales WHERE id = ? AND workspace_id = ?");
            $del->execute([$saleId, $w]);
            $sales_message = 'Sale deleted.';
        }
    }

    if (isset($_POST['admin_delete_workspace']) && $auth && $auth['type'] === 'admin') {
        $workspaceId = intval($_POST['workspace_id'] ?? 0);
        if ($workspaceId > 0) {
            deleteWorkspaceData($pdo, $workspaceId);
            $admin_message = 'Workspace and related data deleted.';
        }
    }

    if (isset($_POST['admin_approve_seller']) && $auth && $auth['type'] === 'admin') {
        $userId = intval($_POST['user_id'] ?? 0);
        if ($userId > 0) {
            $pdo->prepare("UPDATE users SET seller_status = 'approved' WHERE id = ? AND role = 'seller'")->execute([$userId]);
            $admin_message = 'Seller account approved.';
        }
    }

    // Logout
    if (isset($_POST['logout'])) {
        session_unset();
        session_destroy();
        header("Location: " . strtok($_SERVER["REQUEST_URI"],'?'));
        exit;
    }
}

/* -------------------------
   Fetch public listings (workspaces) and sample data
   ------------------------- */
function fetchWorkspaces(PDO $pdo, $q = null, bool $includeHidden = false) {
    $excludedSlugs = ['uk-pizza', 'soma-painter', 'fashion-clothes', 'super-car', 'hama-mobiliat'];
    $hiddenCondition = $includeHidden ? '' : "WHERE slug NOT IN ('" . implode("','", $excludedSlugs) . "')";

    if ($q) {
        $like = "%$q%";
        if ($includeHidden) {
            $stmt = $pdo->prepare("SELECT id,slug,name,store_name,logo,phone,theme_color FROM workspaces WHERE (name LIKE ? OR store_name LIKE ?) LIMIT 100");
            $stmt->execute([$like, $like]);
        } else {
            $stmt = $pdo->prepare("SELECT id,slug,name,store_name,logo,phone,theme_color FROM workspaces WHERE (name LIKE ? OR store_name LIKE ?) AND slug NOT IN ('uk-pizza','soma-painter','fashion-clothes','super-car','hama-mobiliat') LIMIT 100");
            $stmt->execute([$like, $like]);
        }
    } else {
        if ($includeHidden) {
            $stmt = $pdo->query("SELECT id,slug,name,store_name,logo,phone,theme_color FROM workspaces ORDER BY id ASC LIMIT 100");
        } else {
            $stmt = $pdo->query("SELECT id,slug,name,store_name,logo,phone,theme_color FROM workspaces WHERE slug NOT IN ('uk-pizza','soma-painter','fashion-clothes','super-car','hama-mobiliat') ORDER BY id ASC LIMIT 100");
        }
    }
    return $stmt->fetchAll();
}
$search = trim($_GET['q'] ?? '');
$adminQuery = trim($_GET['admin_q'] ?? '');
$shopSlug = trim($_GET['shop'] ?? '');
$selectedCategory = trim($_GET['cat'] ?? '');
$subscription_message = '';
$selectedSubcategory = trim($_GET['subcat'] ?? '');
$selectedBrand = trim($_GET['brand'] ?? '');
$selectedTag = trim($_GET['tag'] ?? '');
$sortBy = trim($_GET['sort'] ?? 'newest');
$selectedProductId = isset($_GET['product']) ? intval($_GET['product']) : 0;
$selectedWorkspace = null;
$showMyShop = isset($_GET['my_shop']) && $auth && $auth['type'] === 'seller';
$showAdmin = isset($_GET['admin']) && $auth && $auth['type'] === 'admin';
$sellerWorkspace = null;
$salesFrom = trim($_GET['sale_from'] ?? '');
$salesTo = trim($_GET['sale_to'] ?? '');
$salesQuery = trim($_GET['sale_q'] ?? '');
$analytics = [];
$salesSummary = [
    'orders' => 0,
    'units' => 0,
    'revenue' => 0,
    'today_revenue' => 0,
    'week_revenue' => 0,
    'month_revenue' => 0,
    'year_revenue' => 0,
    'yesterday_revenue' => 0,
    'prev_week_revenue' => 0,
    'prev_month_revenue' => 0,
    'prev_year_revenue' => 0,
    'today_change' => 0,
    'week_change' => 0,
    'month_change' => 0,
    'year_change' => 0,
    'best_products' => [],
    'category_revenue' => [],
    'daily_series' => [],
    'monthly_series' => [],
];
$salesRecords = [];
$sales_message = '';
$admin_message = '';
$inquiries = [];
$selectedProducts = [];
$selectedCategories = [];
$selectedProduct = null;
$galleryImages = [];
$availableBrands = [];
$availableTags = [];
$adminSummary = [];
$adminWorkspaces = [];
if ($auth && $auth['type'] === 'seller') {
    $sellerWorkspace = workspaceById($pdo, intval($auth['workspace_id']));
    if ($sellerWorkspace) {
        $analytics = analyticsSummary($pdo, intval($sellerWorkspace['id']));
        $salesSummary = salesSummary($pdo, intval($sellerWorkspace['id']), $salesFrom, $salesTo, $salesQuery);
        $salesRecords = fetchSalesRecords($pdo, intval($sellerWorkspace['id']), $salesFrom, $salesTo, $salesQuery);
    }
}
$pendingSellers = [];
if ($auth && $auth['type'] === 'admin') {
    $adminSummary = platformSummary($pdo);
    $adminWorkspaces = fetchWorkspaces($pdo, $adminQuery, true);
    $stmt = $pdo->prepare("SELECT u.id,u.email,u.name,u.workspace_id,u.seller_status,w.slug,w.store_name FROM users u LEFT JOIN workspaces w ON w.id = u.workspace_id WHERE u.role = 'seller' AND u.seller_status = 'pending' ORDER BY u.created_at DESC LIMIT 100");
    $stmt->execute();
    $pendingSellers = $stmt->fetchAll();
}
if ($shopSlug !== '') {
    $selectedWorkspace = workspaceBySlug($pdo, $shopSlug, $showAdmin);
    if ($selectedWorkspace) {
        trackEvent($pdo, intval($selectedWorkspace['id']), 'visit', null, 'web', 'Unknown', 'Unknown');
        $selectedProducts = productsByWorkspace($pdo, intval($selectedWorkspace['id']));
        $selectedCategories = categoriesByWorkspace($pdo, intval($selectedWorkspace['id']));
        if ($selectedProductId > 0) {
            $selectedProduct = productById($pdo, intval($selectedWorkspace['id']), $selectedProductId);
            if ($selectedProduct) {
                trackEvent($pdo, intval($selectedWorkspace['id']), 'product_view', intval($selectedProduct['id']), 'web', 'Unknown', 'Unknown');
                $galleryImages = [];
                if (!empty($selectedProduct['gallery_images'])) {
                    $galleryImages = json_decode($selectedProduct['gallery_images'], true) ?: [];
                }
                if (empty($galleryImages) && !empty($selectedProduct['image_url'])) {
                    $galleryImages[] = $selectedProduct['image_url'];
                }
                if (!empty($selectedProduct['image_url']) && !in_array($selectedProduct['image_url'], $galleryImages, true)) {
                    array_unshift($galleryImages, $selectedProduct['image_url']);
                }
            }
        }
        $filteredProducts = [];
        foreach ($selectedProducts as $product) {
            if (!productMatchesFilters($product, $search, $selectedCategory, $selectedSubcategory, $selectedBrand, $selectedTag)) {
                continue;
            }
            $filteredProducts[] = $product;
            $brand = trim((string) ($product['brand'] ?? ''));
            if ($brand !== '' && !in_array($brand, $availableBrands, true)) {
                $availableBrands[] = $brand;
            }
            foreach (parseTags((string) ($product['tags'] ?? '')) as $tag) {
                if ($tag !== '' && !in_array($tag, $availableTags, true)) {
                    $availableTags[] = $tag;
                }
            }
        }
        $selectedProducts = sortProductsByMode($filteredProducts, $sortBy);
    }
}
$workspaces = fetchWorkspaces($pdo, $search);

/* -------------------------
   Helper: fetch products count
   ------------------------- */
function productsCount(PDO $pdo, $workspace_id) {
    $stmt = $pdo->prepare("SELECT COUNT(*) AS c FROM products WHERE workspace_id = ?");
    $stmt->execute([$workspace_id]);
    $r = $stmt->fetch();
    return intval($r['c'] ?? 0);
}

function workspaceBySlug(PDO $pdo, $slug, bool $includeHidden = false) {
    $excludedSlugs = ['uk-pizza', 'soma-painter', 'fashion-clothes', 'super-car', 'hama-mobiliat'];
    if (!$includeHidden && in_array($slug, $excludedSlugs, true)) {
        return null;
    }
    $stmt = $pdo->prepare("SELECT id,slug,name,store_name,logo,cover_image,phone,theme_color,primary_color,secondary_color,description,address,social_links,business_hours,website FROM workspaces WHERE slug = ? LIMIT 1");
    $stmt->execute([$slug]);
    return $stmt->fetch();
}

function workspaceById(PDO $pdo, int $id) {
    $stmt = $pdo->prepare("SELECT id,slug,name,store_name,logo,cover_image,phone,theme_color,primary_color,secondary_color,description,address,social_links,business_hours,website FROM workspaces WHERE id = ? LIMIT 1");
    $stmt->execute([$id]);
    return $stmt->fetch();
}

function platformSummary(PDO $pdo): array {
    $totals = $pdo->query("SELECT COUNT(*) AS total_workspaces FROM workspaces")->fetch();
    $products = $pdo->query("SELECT COUNT(*) AS total_products FROM products")->fetch();
    $sales = $pdo->query("SELECT COUNT(*) AS total_sales, COALESCE(SUM(total_price),0) AS total_revenue FROM sales")->fetch();
    $sellers = $pdo->query("SELECT COUNT(DISTINCT workspace_id) AS total_sellers FROM users WHERE workspace_id > 0")->fetch();
    $customers = $pdo->query("SELECT COUNT(*) AS total_customers FROM users WHERE workspace_id = 0")->fetch();

    return [
        'workspaces' => intval($totals['total_workspaces'] ?? 0),
        'products' => intval($products['total_products'] ?? 0),
        'sales' => intval($sales['total_sales'] ?? 0),
        'revenue' => floatval($sales['total_revenue'] ?? 0),
        'sellers' => intval($sellers['total_sellers'] ?? 0),
        'customers' => intval($customers['total_customers'] ?? 0),
    ];
}

function productsByWorkspace(PDO $pdo, $workspace_id) {
    $stmt = $pdo->prepare("SELECT p.*, c.name AS category_name, pc.name AS parent_category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id LEFT JOIN categories pc ON c.parent_id = pc.id WHERE p.workspace_id = ? ORDER BY p.id DESC");
    $stmt->execute([$workspace_id]);
    return $stmt->fetchAll();
}

function deleteWorkspaceData(PDO $pdo, int $workspaceId): void {
    $pdo->prepare("DELETE FROM products WHERE workspace_id = ?")->execute([$workspaceId]);
    $pdo->prepare("DELETE FROM sales WHERE workspace_id = ?")->execute([$workspaceId]);
    $pdo->prepare("DELETE FROM inquiries WHERE workspace_id = ?")->execute([$workspaceId]);
    $pdo->prepare("DELETE FROM subscriptions WHERE workspace_id = ?")->execute([$workspaceId]);
    $pdo->prepare("DELETE FROM payments WHERE workspace_id = ?")->execute([$workspaceId]);
    $pdo->prepare("DELETE FROM categories WHERE workspace_id = ?")->execute([$workspaceId]);
    $pdo->prepare("DELETE FROM users WHERE workspace_id = ?")->execute([$workspaceId]);
    $pdo->prepare("DELETE FROM workspaces WHERE id = ?")->execute([$workspaceId]);
}

function categoriesByWorkspace(PDO $pdo, $workspace_id) {
    $stmt = $pdo->prepare("SELECT id,name,parent_id FROM categories WHERE workspace_id = ? ORDER BY name ASC");
    $stmt->execute([$workspace_id]);
    return $stmt->fetchAll();
}

function productById(PDO $pdo, $workspace_id, $product_id) {
    $stmt = $pdo->prepare("SELECT p.*, c.name AS category_name, pc.name AS parent_category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id LEFT JOIN categories pc ON c.parent_id = pc.id WHERE p.workspace_id = ? AND p.id = ? LIMIT 1");
    $stmt->execute([$workspace_id, $product_id]);
    return $stmt->fetch();
}

/* -------------------------
   Safe output helper
   ------------------------- */
function e($s){ return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

function renderGrowthBadge(?float $change, string $vsLabel, string $noDataLabel): string {
    if ($change === null) {
        return '<span class="small-muted text-xs">' . e($noDataLabel) . '</span>';
    }
    $rounded = round($change, 1);
    $isUp = $rounded > 0;
    $isFlat = abs($rounded) < 0.05;
    $colorClass = $isFlat ? 'text-slate-400' : ($isUp ? 'text-emerald-400' : 'text-rose-400');
    $arrow = $isFlat ? '•' : ($isUp ? '▲' : '▼');
    $sign = $isUp ? '+' : '';
    return '<span class="text-xs font-semibold ' . $colorClass . '">' . $arrow . ' ' . e($sign . number_format($rounded, 1) . '%') . '</span> <span class="small-muted text-xs">' . e($vsLabel) . '</span>';
}

function normalizePhoneForWhatsApp($phone) {
    $phone = preg_replace('/[^0-9+]/', '', (string) $phone);
    if ($phone === '') {
        return '';
    }
    if (strpos($phone, '+') === 0) {
        return ltrim($phone, '+');
    }
    return $phone;
}

function whatsappLink($phone, $text) {
    $phone = normalizePhoneForWhatsApp($phone);
    if ($phone === '') {
        return '#';
    }
    return 'https://wa.me/' . rawurlencode($phone) . '?text=' . rawurlencode($text);
}

function shareUrl(string $path): string {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return $protocol . '://' . $host . '/' . ltrim($path, '/');
}

function qrDataUrl(string $text): string {
    $encoded = rawurlencode($text);
    return 'https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=' . $encoded;
}

?>
<!doctype html>
<html lang="<?= e($lang) ?>" dir="<?= in_array($lang, ['ar','ku'], true) ? 'rtl' : 'ltr' ?>">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title><?= e(translate('site_title', $lang, $translations)) ?></title>

  <!-- Tailwind CDN for MVP -->
  <script src="https://cdn.tailwindcss.com"></script>

  <style>
    :root{
      color-scheme: dark;
      --bg:#071021;
      --bg-2:#071827;
      --card:rgba(255,255,255,0.03);
      --card-2:rgba(255,255,255,0.02);
      --text:#e6eef8;
      --muted:#94a3b8;
      --border:rgba(255,255,255,0.08);
      --border-strong:rgba(255,255,255,0.12);
      --input-bg:transparent;
      --input-text:#e6eef8;
      --btn-text:#e6eef8;
      --pill-bg:rgba(255,255,255,0.03);
      --hero-bg:linear-gradient(135deg, rgba(99,102,241,0.18), rgba(14,165,164,0.12));
      --shadow:rgba(2,6,23,0.24);
      --modal-bg:rgba(2,6,23,0.7);
      --modal-surface:linear-gradient(180deg, #071827, #071827);
      --link:#9fb0c8;
    }
    body[data-theme="light"]{
      color-scheme: light;
      --bg:#f5f7fb;
      --bg-2:#ffffff;
      --card:#ffffff;
      --card-2:#f8fafc;
      --text:#0f172a;
      --muted:#64748b;
      --border:rgba(15,23,42,0.08);
      --border-strong:rgba(15,23,42,0.12);
      --input-bg:#fff;
      --input-text:#0f172a;
      --btn-text:#0f172a;
      --pill-bg:rgba(15,23,42,0.04);
      --hero-bg:linear-gradient(135deg, rgba(129,140,248,0.16), rgba(45,212,191,0.12));
      --shadow:rgba(15,23,42,0.12);
      --modal-bg:rgba(15,23,42,0.4);
      --modal-surface:linear-gradient(180deg, #ffffff, #f8fafc);
      --link:#475569;
    }
    body{ background: linear-gradient(180deg,var(--bg) 0%, var(--bg-2) 100%); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial; }
    .search-box{ background: linear-gradient(90deg, var(--card), var(--card-2)); border:1px solid var(--border); padding:8px; border-radius:12px; box-shadow: inset 0 1px 0 rgba(255,255,255,0.03); }
    .card{ background: linear-gradient(180deg, var(--card), var(--card-2)); border:1px solid var(--border); padding:10px; border-radius:12px; transition:transform .15s ease, box-shadow .15s ease, border-color .15s ease; box-shadow:0 6px 18px rgba(2,6,23,0.08); }
    .card:hover{ transform:translateY(-2px); box-shadow:0 12px 24px rgba(2,6,23,0.10); border-color:var(--border-strong); }
    .small-muted{ color:var(--muted); font-size:13px; }
    .btn-ghost{ background:transparent; border:1px solid var(--border); padding:6px 10px; border-radius:10px; color:var(--btn-text); transition:all .2s ease; }
    .btn-ghost:hover{ background:rgba(255,255,255,0.05); transform:translateY(-1px); }
    body[data-theme="light"] .btn-ghost:hover{ background:rgba(15,23,42,0.05); }
    .logo-sm{ width:44px;height:44px;border-radius:8px;object-fit:cover;border:1px solid var(--border); }
    .pill{ background:var(--pill-bg); padding:6px 10px;border-radius:999px;font-size:13px; }
    .input-dark{ background:var(--input-bg); border:1px solid var(--border); padding:8px 10px;border-radius:8px;color:var(--input-text); }
    .modal-backdrop{ position:fixed;inset:0;background:var(--modal-bg);display:flex;align-items:center;justify-content:center;z-index:60; }
    .modal{ background:var(--modal-surface); border:1px solid var(--border); padding:18px;border-radius:12px; width:100%; max-width:520px; box-shadow:0 20px 60px var(--shadow); }
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
    .site-nav a:hover{ opacity:1; transform:translateY(-1px); }
    .topbar-actions{ display:flex; flex-wrap:wrap; gap:0.75rem; align-items:center; justify-content:flex-end; }
    .topbar-actions .btn-ghost{ padding:0.78rem 1rem; border-radius:999px; }
    .hero-section{ position:relative; overflow:hidden; border-radius:32px; background:linear-gradient(180deg, rgba(255,255,255,0.96), rgba(245,249,255,0.94)); border:1px solid rgba(148,163,184,0.18); padding:4rem 2rem; margin-top:1.5rem; }
    .hero-section::before{ content:''; position:absolute; inset:0; background:radial-gradient(circle at 14% 22%, rgba(59,130,246,0.22), transparent 20%), radial-gradient(circle at 90% 15%, rgba(168,85,247,0.14), transparent 16%), radial-gradient(circle at 50% 78%, rgba(56,189,248,0.12), transparent 18%); pointer-events:none; }
    .hero-copy{ position:relative; z-index:1; }
    .hero-copy h1{ font-size:clamp(2.4rem, 4vw, 4.4rem); line-height:1.02; margin:0; color:#071825; letter-spacing:-0.04em; }
    .hero-copy p{ margin-top:1.5rem; color:#475569; font-size:1.05rem; line-height:1.75; max-width:36rem; }
    .hero-panel{ position:relative; z-index:1; width:100%; min-height:320px; border-radius:32px; overflow:hidden; background:rgba(255,255,255,0.94); border:1px solid rgba(148,163,184,0.22); box-shadow:0 28px 90px rgba(15,23,42,0.08); }
    .hero-panel::before{ content:''; position:absolute; inset:0; background:radial-gradient(circle at 20% 18%, rgba(59,130,246,0.14), transparent 24%), radial-gradient(circle at 84% 22%, rgba(168,85,247,0.1), transparent 20%), radial-gradient(circle at 50% 82%, rgba(34,211,238,0.08), transparent 24%); pointer-events:none; }
    .hero-panel-inner{ position:relative; width:100%; height:100%; display:grid; gap:1rem; grid-template-columns:1fr; padding:2rem; }
    .hero-card{ position:relative; width:100%; min-height:160px; border-radius:28px; background:rgba(15,23,42,0.96); border:1px solid rgba(255,255,255,0.08); box-shadow:0 24px 60px rgba(15,23,42,0.18); color:#fff; padding:1.5rem; display:flex; flex-direction:column; justify-content:space-between; }
    .hero-card::before{ content:''; position:absolute; inset:0; background:radial-gradient(circle at 20% 20%, rgba(59,130,246,0.18), transparent 16%), radial-gradient(circle at 80% 70%, rgba(56,189,248,0.14), transparent 14%); border-radius:28px; opacity:0.8; }
    .hero-card > *{ position:relative; z-index:1; }
    .hero-card-title{ font-size:1.1rem; font-weight:700; margin-bottom:0.75rem; }
    .hero-card-text{ color:rgba(226,238,248,0.92); line-height:1.7; }
    .hero-cta-row{ display:flex; flex-wrap:wrap; gap:1rem; margin-top:2.2rem; align-items:center; }
    .hero-cta-secondary{ border-color:rgba(148,163,184,0.32); background:rgba(245,249,255,0.8); color:#0f172a; }
    .hero-cta-secondary:hover{ background:rgba(241,245,249,1); }
    @media (min-width: 1024px){ .hero-section{ padding:4rem 3rem; } }
    @media (min-width: 1280px){ .hero-panel{ min-height:420px; } }
    .topbar-note{ font-size:0.82rem; color:var(--muted); }
    .hero-visual{ position:relative; }
    .btn-primary{ display:inline-flex; align-items:center; justify-content:center; gap:.5rem; background:linear-gradient(90deg, #4f46e5, #14b8a6); color:#fff; border:none; padding:.95rem 1.6rem; border-radius:999px; font-weight:700; box-shadow:0 18px 40px rgba(59,130,246,0.22); transition:transform .2s ease, opacity .2s ease; }
    .btn-primary:hover{ transform:translateY(-1px); opacity:.98; }
    .dashboard-header{ display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:.6rem; margin-bottom:.75rem; }
    .dashboard-header .title{ font-size:.95rem; font-weight:700; letter-spacing:-0.01em; }
    .dashboard-stat-grid{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:.4rem; }
    @media (min-width: 640px){ .dashboard-stat-grid{ grid-template-columns:repeat(4,minmax(0,1fr)); } }
    .dashboard-stat{ background:rgba(255,255,255,0.03); border:1px solid var(--border); border-radius:10px; padding:7px 9px;}
    .dashboard-stat .label{ display:block; color:var(--muted); text-transform:uppercase; font-size:9px; letter-spacing:0.1em; margin-bottom:0.25rem; }
    .dashboard-stat .value{ font-size:.9rem; font-weight:700; line-height:1.1; color:var(--text); }
    .dashboard-card{ padding:.55rem; }
    .dashboard-panel{ background:rgba(255,255,255,0.03); border:1px solid var(--border); border-radius:10px; padding:.5rem; }
    .dashboard-actions{ display:flex; flex-wrap:wrap; gap:.4rem; }
    .dashboard-actions .btn-ghost{ justify-content:center; padding:5px 10px; font-size:.8rem; }
    .dashboard-table{ width:100%; border-collapse:separate; border-spacing:0; background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.06); border-radius:10px; overflow:hidden; font-size:.85rem; }
    .dashboard-table th, .dashboard-table td{ padding:6px 8px; }
    .dashboard-table thead{ background:rgba(255,255,255,0.03); }
    .dashboard-table tbody tr:hover{ background:rgba(255,255,255,0.02); }
    .map-card{ background:rgba(255,255,255,0.04); border:1px solid var(--border); border-radius:18px; padding:16px; }
    .workspace-map{ width:100%; min-height:220px; border:0; border-radius:14px; }
    .stat-pill{ background:rgba(255,255,255,0.07); border:1px solid var(--border); padding:8px 12px; border-radius:999px; font-size:13px; color:var(--text); }
    body[data-theme="light"] .stat-pill{ background:rgba(255,255,255,0.7); }
    .chip{ background:linear-gradient(135deg, rgba(255,255,255,0.09), rgba(255,255,255,0.04)); border:1px solid var(--border); color:var(--text); padding:8px 12px; border-radius:999px; font-size:13px; transition:all .2s ease; font-weight:600; box-shadow:0 6px 16px rgba(2,6,23,0.08); }
    .chip:hover{ transform:translateY(-1px); border-color:var(--border-strong); box-shadow:0 10px 22px rgba(2,6,23,0.14); }
    .chip-badge{ background:linear-gradient(135deg, rgba(99,102,241,0.24), rgba(45,212,191,0.18)); border:1px solid rgba(255,255,255,0.16); color:var(--text); padding:8px 12px; border-radius:999px; font-size:13px; font-weight:700; box-shadow:0 8px 20px rgba(2,6,23,0.16); }
    body[data-theme="light"] .chip{ background:rgba(255,255,255,0.75); }
    .empty-state{ border:1px dashed var(--border); background:rgba(255,255,255,0.03); padding:22px; border-radius:16px; text-align:center; }
    body[data-theme="light"] .empty-state{ background:rgba(248,250,252,0.9); }
    .gallery-thumb{ width:72px; height:72px; object-fit:cover; border-radius:10px; border:1px solid var(--border); cursor:pointer; }
    .gallery-thumb.active{ border-color: #2dd4bf; box-shadow: 0 0 0 2px rgba(45,212,191,0.18); }
    .theme-swatch{ width:32px; height:32px; border-radius:10px; cursor:pointer; border:2px solid transparent; transition:all .2s ease; }
    .theme-swatch.selected{ border-color:#fff; transform:scale(1.05); }
    .theme-swatch-grid{ display:grid; grid-template-columns:repeat(10,minmax(0,1fr)); gap:8px; }
    .shop-preview-card{ background:linear-gradient(180deg,var(--preview-secondary,#111827),var(--preview-primary,#0ea5a4)); }
    .image-zoom-modal{ position:fixed; inset:0; background:rgba(2,6,23,0.8); z-index:80; display:none; align-items:center; justify-content:center; padding:20px; }
    .image-zoom-modal img{ max-width:min(92vw, 900px); max-height:88vh; object-fit:contain; border-radius:16px; border:1px solid var(--border); }
  </style>
</head>
<body data-theme="<?= e($theme) ?>">
  <div class="max-w-6xl mx-auto p-6">
    <!-- Top bar -->
    <div class="topbar mb-6">
      <div class="flex flex-col gap-6 xl:flex-row xl:items-center xl:justify-between">
        <div class="flex flex-col gap-4 xl:flex-row xl:items-center xl:gap-6">
          <div class="flex items-center gap-3">
            <img src="uploads/logo.svg" alt="Reyonic logo" class="w-12 h-12 rounded-2xl object-cover border border-white/10 shadow-lg shadow-cyan-500/10">
            <div>
              <div class="text-lg font-semibold tracking-tight">Reyonic</div>
              <div class="small-muted"><?= e(translate('site_subtitle', $lang, $translations)) ?></div>
            </div>
          </div>
          <nav class="site-nav">
            <a href="?q=&lang=<?= urlencode($lang) ?>" class="text-sm">Home</a>
            <a href="?q=&lang=<?= urlencode($lang) ?>#workspaces" class="text-sm">Products</a>
            <a href="about.php?lang=<?= urlencode($lang) ?>" class="text-sm">About</a>
            <a href="about.php?lang=<?= urlencode($lang) ?>#contact" class="text-sm">Contact</a>
          </nav>
        </div>

        <div class="topbar-actions">
          <form method="get" class="flex items-center gap-2">
            <input type="hidden" name="q" value="<?= e($search) ?>">
            <input type="hidden" name="lang" value="<?= e($lang) ?>">
            <input type="hidden" name="theme" value="<?= $theme === 'dark' ? 'light' : 'dark' ?>">
            <?php if ($showMyShop): ?><input type="hidden" name="my_shop" value="1"><?php endif; ?>
            <button type="submit" class="btn-ghost" title="<?= e(translate('theme_toggle', $lang, $translations)) ?>">
              <?= $theme === 'dark' ? '☀️ ' . e(translate('light', $lang, $translations)) : '🌙 ' . e(translate('dark', $lang, $translations)) ?>
            </button>
          </form>
          <form method="get" class="flex items-center gap-2">
            <input type="hidden" name="q" value="<?= e($search) ?>">
            <input type="hidden" name="theme" value="<?= e($theme) ?>">
            <?php if ($showMyShop): ?><input type="hidden" name="my_shop" value="1"><?php endif; ?>
            <label class="small-muted text-xs"><?= e(translate('language', $lang, $translations)) ?></label>
            <select name="lang" class="input-dark w-28" onchange="this.form.submit()">
              <?php foreach ($availableLanguages as $code => $label): ?>
                <option value="<?= e($code) ?>" <?= $lang === $code ? 'selected' : '' ?>><?= e($label) ?></option>
              <?php endforeach; ?>
            </select>
          </form>
          <?php if ($auth): ?>
            <div class="pill"><?= e($auth['name']) ?> (<?= e(translateRole($auth['type'], $lang, $translations)) ?>)</div>
            <?php if ($auth['type'] === 'admin'): ?>
              <a href="?admin=1&lang=<?= urlencode($lang) ?>" class="btn-primary"><?= e(translate('admin', $lang, $translations)) ?></a>
            <?php elseif ($auth['type'] === 'seller'): ?>
              <a href="?my_shop=1&lang=<?= urlencode($lang) ?>" class="btn-primary"><?= e(translate('my_shop', $lang, $translations)) ?></a>
              <button id="openAdminLogin" class="btn-primary"><?= e(translate('admin', $lang, $translations)) ?></button>
            <?php endif; ?>
            <form method="post" style="display:inline">
              <?= csrfField() ?>
              <button name="logout" class="btn-ghost"><?= e(translate('logout', $lang, $translations)) ?></button>
            </form>
          <?php else: ?>
            <button id="openLogin" class="btn-primary"><?= e(translate('login', $lang, $translations)) ?></button>
            <button id="openAdminLogin" class="btn-ghost"><?= e(translate('admin', $lang, $translations)) ?></button>
          <?php endif; ?>
        </div>
      </div>

      <?php if (!($auth && ($auth['type'] === 'seller'))): ?>
      <?php endif; ?>
    </div>

    <section class="hero-section mb-8">
      <div class="grid gap-8 xl:grid-cols-[1.1fr_0.9fr] xl:items-center">
        <div class="hero-copy">
          <div class="chip-badge mb-4"><?= e(translate('hero_badge', $lang, $translations)) ?></div>
          <h1 class="font-semibold text-white"><?= e(translate('hero_title', $lang, $translations)) ?></h1>
          <p class="mt-5 text-base leading-8 text-slate-200/90"><?= e(translate('hero_subtitle', $lang, $translations)) ?></p>
          <div class="hero-cta-row">
            <a href="?q=&lang=<?= urlencode($lang) ?>" class="btn-primary"><?= e(translate('hero_cta', $lang, $translations)) ?></a>
            <a href="?admin=1&lang=<?= urlencode($lang) ?>" class="hero-cta-secondary"><?= e(translate('hero_secondary', $lang, $translations)) ?></a>
          </div>
        </div>
        <div class="hero-visual">
          <div class="hero-panel">
            <div class="hero-card"></div>
          </div>
        </div>
      </div>
    </section>

    <?php if ($selectedWorkspace): ?>
      <section class="card mb-6" style="border-color: <?= e($selectedWorkspace['theme_color'] ?: '#0ea5a4') ?>40;">
        <?php if (!empty($selectedWorkspace['cover_image'])): ?>
          <img src="<?= e($selectedWorkspace['cover_image']) ?>" alt="<?= e($selectedWorkspace['store_name'] ?: $selectedWorkspace['name']) ?>" class="w-full h-48 object-cover rounded-lg mb-4 border border-white/10">
        <?php endif; ?>
        <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between mb-4">
          <div class="flex items-center gap-3">
            <img src="<?= e($selectedWorkspace['logo'] ?: $defaultLogo) ?>" alt="<?= e($selectedWorkspace['store_name'] ?: $selectedWorkspace['name']) ?>" class="logo-sm">
            <div>
              <div class="font-semibold"><?= e($selectedWorkspace['store_name'] ?: $selectedWorkspace['name']) ?></div>
              <div class="small-muted text-xs"><?= e($selectedWorkspace['slug']) ?> • <?= sprintf(translate('products_count', $lang, $translations), count($selectedProducts)) ?></div>
            </div>
          </div>
          <a href="?lang=<?= urlencode($lang) ?><?= $search ? '&q=' . urlencode($search) : '' ?>" class="text-sm link-muted">← <?= e(translate('clear_search', $lang, $translations)) ?></a>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-[1.1fr_0.9fr] gap-4">
          <div>
            <?php if (!empty($selectedWorkspace['description'])): ?>
              <div class="small-muted text-sm mb-3"><?= e($selectedWorkspace['description']) ?></div>
            <?php endif; ?>
            <div class="flex flex-wrap gap-2">
              <?php if (!empty($selectedWorkspace['address'])): ?><span class="pill">📍 <?= e($selectedWorkspace['address']) ?></span><?php endif; ?>
              <?php if (!empty($selectedWorkspace['phone'])): ?><span class="pill">📞 <?= e($selectedWorkspace['phone']) ?></span><?php endif; ?>
              <?php if (!empty($selectedWorkspace['business_hours'])): ?><span class="pill">🕒 <?= e($selectedWorkspace['business_hours']) ?></span><?php endif; ?>
              <?php if (!empty($selectedWorkspace['website'])): ?><span class="pill">🔗 <a href="<?= e($selectedWorkspace['website']) ?>" target="_blank" rel="noopener noreferrer"><?= e($selectedWorkspace['website']) ?></a></span><?php endif; ?>
            </div>
          </div>
          <div class="card p-3">
            <div class="font-semibold mb-2"><?= e(translate('contact_social', $lang, $translations)) ?></div>
            <?php if (!empty($selectedWorkspace['social_links'])): ?>
              <div class="small-muted text-sm break-words"><?= e($selectedWorkspace['social_links']) ?></div>
            <?php else: ?>
              <div class="small-muted text-sm"><?= e(translate('no_social', $lang, $translations)) ?></div>
            <?php endif; 
            if (!empty($selectedWorkspace['website'])): ?>
              <div class="mt-2"><a href="<?= e($selectedWorkspace['website']) ?>" target="_blank" rel="noopener noreferrer" class="text-sm link-muted"><?= e(translate('visit_website', $lang, $translations)) ?></a></div>
            <?php endif; ?>
          </div>
        </div>

        <?php if (!empty($selectedWorkspace['cover_image'])): ?>
          <img src="<?= e($selectedWorkspace['cover_image']) ?>" alt="cover" class="w-full h-40 object-cover rounded-lg mb-4 border border-white/10">
        <?php endif; ?>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div class="card md:col-span-2">
            <div class="font-semibold mb-2"><?= e(translate('shop_profile', $lang, $translations)) ?></div>
            <div class="small-muted text-sm"><?= e($selectedWorkspace['description'] ?: translate('default_shop_bio', $lang, $translations)) ?></div>
            <?php if (!empty($selectedWorkspace['address'])): ?><div class="small-muted text-sm mt-2">📍 <?= e($selectedWorkspace['address']) ?></div><?php endif; ?>
            <?php if (!empty($selectedWorkspace['business_hours'])): ?><div class="small-muted text-sm mt-2">🕒 <?= e($selectedWorkspace['business_hours']) ?></div><?php endif; ?>
            <?php if (!empty($selectedWorkspace['social_links'])): ?><div class="small-muted text-sm mt-2">🔗 <?= e($selectedWorkspace['social_links']) ?></div><?php endif; ?>
            <?php if (!empty($selectedWorkspace['address'])): ?>
              <div class="map-card mt-4">
                <div class="font-semibold mb-2"><?= e(translate('location_map', $lang, $translations)) ?></div>
                <iframe
                  src="https://www.google.com/maps?q=<?= rawurlencode($selectedWorkspace['address']) ?>&output=embed"
                  class="workspace-map"
                  loading="lazy"
                  referrerpolicy="no-referrer-when-downgrade"
                ></iframe>
                <div class="small-muted text-xs mt-2"><?= e(translate('open_maps', $lang, $translations)) ?></div>
              </div>
            <?php endif; ?>
          </div>
          <div class="card">
            <div class="font-semibold mb-2"><?= e(translate('quick_actions', $lang, $translations)) ?></div>
            <div class="flex flex-wrap gap-2">
              <a class="inline-flex items-center gap-1 rounded-full border border-emerald-400/30 bg-emerald-500/10 px-3 py-1.5 text-sm font-semibold text-emerald-300 hover:bg-emerald-500/20" href="<?= e(whatsappLink($selectedWorkspace['phone'] ?: $defaultPhone, 'Hello, I want to order from ' . ($selectedWorkspace['store_name'] ?: $selectedWorkspace['name']) . '.')) ?>" target="_blank" rel="noopener noreferrer">💬 WhatsApp</a>
              <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="?shop=<?= urlencode($selectedWorkspace['slug']) ?>&lang=<?= urlencode($lang) ?>">🛍️ <?= e(translate('browse', $lang, $translations)) ?></a>
            </div>
            <div class="mt-3 flex flex-wrap gap-2">
              <?php $storeShareUrl = shareUrl('index.php?shop=' . urlencode($selectedWorkspace['slug']) . '&lang=' . urlencode($lang)); ?>
              <a class="text-sm link-muted" href="https://www.facebook.com/sharer/sharer.php?u=<?= rawurlencode($storeShareUrl) ?>" target="_blank" rel="noopener noreferrer">📣 <?= e(translate('share_btn', $lang, $translations)) ?></a>
              <a class="text-sm link-muted" href="https://wa.me/?text=<?= rawurlencode('Check this store: ' . $storeShareUrl) ?>" target="_blank" rel="noopener noreferrer">💬 WhatsApp</a>
              <a class="text-sm link-muted" href="<?= e($storeShareUrl) ?>" target="_blank" rel="noopener noreferrer">🔗 <?= e(translate('copy_link', $lang, $translations)) ?></a>
            </div>
            <div class="mt-3 rounded-lg border border-white/10 p-2">
              <div class="small-muted text-xs mb-2"><?= e(translate('qr_code', $lang, $translations)) ?></div>
              <img src="<?= e(qrDataUrl($storeShareUrl)) ?>" alt="Store QR" class="w-24 h-24 rounded-lg border border-white/10 bg-white p-1">
              <div class="small-muted text-[11px] mt-2"><?= e(translate('qr_print_ready', $lang, $translations)) ?></div>
            </div>
          </div>
        </div>

        <div class="flex flex-wrap gap-2 mb-4">
          <span class="chip-badge">🗂️ <?= e(translate('store_categories', $lang, $translations)) ?></span>
          <?php if (!empty($selectedCategories)): foreach ($selectedCategories as $cat): ?>
            <a class="chip" href="?shop=<?= urlencode($selectedWorkspace['slug']) ?>&lang=<?= urlencode($lang) ?>&cat=<?= urlencode($cat['name']) ?>"><?= e($cat['name']) ?></a>
          <?php endforeach; else: ?><span class="chip"><?= e(translate('general', $lang, $translations)) ?></span><?php endif; ?>
        </div>

        <form method="get" class="card mb-4">
          <input type="hidden" name="shop" value="<?= e($selectedWorkspace['slug']) ?>">
          <input type="hidden" name="lang" value="<?= e($lang) ?>">
          <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-2">
            <input name="q" value="<?= e($search) ?>" class="input-dark" placeholder="<?= e(translate('search_products', $lang, $translations)) ?>">
            <select name="cat" class="input-dark">
              <option value=""><?= e(translate('all_categories', $lang, $translations)) ?></option>
              <?php foreach ($selectedCategories as $cat): ?>
                <option value="<?= e($cat['name']) ?>" <?= $selectedCategory === $cat['name'] ? 'selected' : '' ?>><?= e($cat['name']) ?></option>
              <?php endforeach; ?>
            </select>
            <select name="subcat" class="input-dark">
              <option value=""><?= e(translate('all_subcategories', $lang, $translations)) ?></option>
              <?php foreach ($selectedCategories as $cat): if (!empty($cat['parent_id'])): ?>
                <option value="<?= e($cat['name']) ?>" <?= $selectedSubcategory === $cat['name'] ? 'selected' : '' ?>><?= e($cat['name']) ?></option>
              <?php endif; endforeach; ?>
            </select>
            <select name="brand" class="input-dark">
              <option value=""><?= e(translate('all_brands', $lang, $translations)) ?></option>
              <?php foreach ($availableBrands as $brand): ?>
                <option value="<?= e($brand) ?>" <?= $selectedBrand === $brand ? 'selected' : '' ?>><?= e($brand) ?></option>
              <?php endforeach; ?>
            </select>
            <select name="tag" class="input-dark">
              <option value=""><?= e(translate('all_tags', $lang, $translations)) ?></option>
              <?php foreach ($availableTags as $tag): ?>
                <option value="<?= e($tag) ?>" <?= $selectedTag === $tag ? 'selected' : '' ?>><?= e($tag) ?></option>
              <?php endforeach; ?>
            </select>
            <select name="sort" class="input-dark">
              <option value="newest" <?= $sortBy === 'newest' ? 'selected' : '' ?>><?= e(translate('sort_newest', $lang, $translations)) ?></option>
              <option value="price_asc" <?= $sortBy === 'price_asc' ? 'selected' : '' ?>><?= e(translate('sort_price_asc', $lang, $translations)) ?></option>
              <option value="price_desc" <?= $sortBy === 'price_desc' ? 'selected' : '' ?>><?= e(translate('sort_price_desc', $lang, $translations)) ?></option>
              <option value="oldest" <?= $sortBy === 'oldest' ? 'selected' : '' ?>><?= e(translate('sort_oldest', $lang, $translations)) ?></option>
            </select>
          </div>
          <div class="flex flex-wrap gap-2 mt-3">
            <button class="px-3 py-2 bg-cyan-600 rounded text-sm"><?= e(translate('apply_filters', $lang, $translations)) ?></button>
            <a href="?shop=<?= urlencode($selectedWorkspace['slug']) ?>&lang=<?= urlencode($lang) ?>" class="px-3 py-2 border border-white/10 rounded text-sm"><?= e(translate('reset', $lang, $translations)) ?></a>
          </div>
        </form>

        <div class="card mb-4 border-white/10">
          <div class="font-semibold"><?= e(translate('contact_store_title', $lang, $translations)) ?></div>
          <div class="small-muted text-sm mt-2"><?= e(translate('contact_store_desc', $lang, $translations)) ?></div>
          <div class="mt-3 flex flex-wrap gap-2">
            <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="<?= e(whatsappLink($selectedWorkspace['phone'] ?: $defaultPhone, 'Hello, I would like more information about ' . ($selectedWorkspace['store_name'] ?: $selectedWorkspace['name']) . '.')) ?>" target="_blank" rel="noopener noreferrer">💬 <?= e(translate('contact_store', $lang, $translations)) ?></a>
            <?php if (!empty($selectedWorkspace['website'])): ?><a class="inline-flex items-center gap-1 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-sm font-semibold text-white hover:bg-white/10" href="<?= e($selectedWorkspace['website']) ?>" target="_blank" rel="noopener noreferrer">🌐 <?= e(translate('visit_website', $lang, $translations)) ?></a><?php endif; ?>
          </div>
        </div>

        <?php if (empty($selectedProducts)): ?>
          <div class="empty-state">
            <div class="font-semibold"><?= e(translate('no_products', $lang, $translations)) ?></div>
            <div class="small-muted mt-2"><?= e(translate('no_products_store', $lang, $translations)) ?></div>
          </div>
        <?php else: ?>
          <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            <?php foreach ($selectedProducts as $p): ?>
              <div class="card">
                <?php if (!empty($p['image_url'])): ?>
                  <img src="<?= e($p['image_url']) ?>" alt="<?= e($p['name']) ?>" class="w-full h-40 object-cover rounded-lg mb-3 border border-white/10">
                <?php else: ?>
                  <div class="w-full h-40 mb-3 rounded-lg border border-dashed border-white/10 flex items-center justify-center bg-black/20 text-sm text-slate-300">
                    <?= e(translate('no_image', $lang, $translations)) ?>
                  </div>
                <?php endif; ?>
                <div class="font-semibold"><?= e($p['name']) ?></div>
                <div class="small-muted text-xs mt-1"><?= e(($p['parent_category_name'] ? $p['parent_category_name'] . ' / ' : '') . ($p['category_name'] ?? '')) ?> • <?= e(number_format(floatval($p['price']), 0)) ?> IQD</div>
                <?php if (!empty($p['brand'])): ?>
                  <div class="small-muted text-xs mt-1"><?= e(translate('brand_label', $lang, $translations)) ?>: <?= e($p['brand']) ?></div>
                <?php endif; ?>
                <?php if (!empty($p['description'])): ?>
                  <div class="small-muted text-sm mt-2"><?= e($p['description']) ?></div>
                <?php endif; ?>
                <?php if (!empty($p['tags'])): ?>
                  <div class="flex flex-wrap gap-1 mt-2">
                    <?php foreach (parseTags((string) $p['tags']) as $tag): ?>
                      <span class="rounded-full bg-white/10 px-2 py-0.5 text-[10px] uppercase tracking-[0.2em] text-slate-300"><?= e($tag) ?></span>
                    <?php endforeach; ?>
                  </div>
                <?php endif; ?>
                <div class="mt-3 flex flex-wrap gap-2">
                  <a class="inline-flex items-center gap-1 rounded-full border border-emerald-400/30 bg-emerald-500/10 px-3 py-1.5 text-sm font-semibold text-emerald-300 hover:bg-emerald-500/20" href="?shop=<?= urlencode($selectedWorkspace['slug']) ?>&lang=<?= urlencode($lang) ?>&product=<?= intval($p['id']) ?>">🔎 <?= e(translate('view_details', $lang, $translations)) ?></a>
                  <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="<?= e(whatsappLink($selectedWorkspace['phone'] ?: $defaultPhone, 'Hello, I would like more information about ' . $p['name'] . '.')) ?>" target="_blank" rel="noopener noreferrer">💬 <?= e(translate('contact_store', $lang, $translations)) ?></a>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </section>
    <?php endif; ?>

    <div class="flex items-center justify-between mb-3">
      <div>
        <div class="text-xl font-semibold"><?= e(translate('featured_stores', $lang, $translations)) ?></div>
        <div class="small-muted"><?= e(translate('featured_subtitle', $lang, $translations)) ?></div>
      </div>
      <?php if ($search): ?>
        <a href="?lang=<?= urlencode($lang) ?>" class="text-sm link-muted"><?= e(translate('clear_search', $lang, $translations)) ?></a>
      <?php endif; ?>
    </div>

    <div class="flex flex-wrap gap-2 mb-4">
      <span class="chip-badge">🏷️ <?= e(translate('categories_title', $lang, $translations)) ?></span>
      <span class="chip"><?= e(translate('category_fashion', $lang, $translations)) ?></span>
      <span class="chip"><?= e(translate('category_electronics', $lang, $translations)) ?></span>
      <span class="chip"><?= e(translate('category_food', $lang, $translations)) ?></span>
      <span class="chip"><?= e(translate('category_beauty', $lang, $translations)) ?></span>
    </div>

    <?php if ($showAdmin): ?>
      <section class="mt-6 p-4 bg-white/5 border border-white/10 rounded">
        <div class="flex flex-col gap-4">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-xl font-semibold"><?= e(translate('admin_dashboard', $lang, $translations)) ?></div>
              <div class="small-muted"><?= e(translate('admin_subtitle', $lang, $translations)) ?></div>
            </div>
            <div class="flex gap-2">
              <a href="?admin=1&lang=<?= urlencode($lang) ?>" class="btn-ghost"><?= e(translate('refresh', $lang, $translations)) ?></a>
              <a href="?lang=<?= urlencode($lang) ?>" class="btn-ghost"><?= e(translate('public_view', $lang, $translations)) ?></a>
            </div>
          </div>

          <?php if (!empty($admin_message)): ?><div class="small-muted text-emerald-300"><?= e(translateMessage($admin_message, $lang, $translations)) ?></div><?php endif; ?>
          <div class="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
            <div class="rounded-lg border border-white/10 p-3"><div class="small-muted text-xs"><?= e(translate('stat_workspaces', $lang, $translations)) ?></div><div class="text-xl font-semibold"><?= e($adminSummary['workspaces'] ?? 0) ?></div></div>
            <div class="rounded-lg border border-white/10 p-3"><div class="small-muted text-xs"><?= e(translate('stat_products', $lang, $translations)) ?></div><div class="text-xl font-semibold"><?= e($adminSummary['products'] ?? 0) ?></div></div>
            <div class="rounded-lg border border-white/10 p-3"><div class="small-muted text-xs"><?= e(translate('stat_sales', $lang, $translations)) ?></div><div class="text-xl font-semibold"><?= e($adminSummary['sales'] ?? 0) ?></div></div>
            <div class="rounded-lg border border-white/10 p-3"><div class="small-muted text-xs"><?= e(translate('stat_revenue', $lang, $translations)) ?></div><div class="text-xl font-semibold"><?= e(number_format($adminSummary['revenue'] ?? 0, 0)) ?> IQD</div></div>
          </div>

          <div class="rounded-lg border border-white/10 p-4 mb-4">
            <form method="get" class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input type="hidden" name="admin" value="1">
              <input type="hidden" name="lang" value="<?= e($lang) ?>">
              <input name="admin_q" class="input-dark w-full" placeholder="<?= e(translate('search_workspaces', $lang, $translations)) ?>" value="<?= e($adminQuery) ?>">
              <button type="submit" class="px-3 py-2 bg-cyan-600 rounded text-sm"><?= e(translate('search_btn', $lang, $translations)) ?></button>
            </form>
          </div>

          <?php if (!empty($pendingSellers)): ?>
            <div class="rounded-lg border border-yellow-400/20 bg-yellow-500/10 p-4 mb-4">
              <div class="font-semibold mb-2"><?= e(translate('pending_sellers_title', $lang, $translations)) ?></div>
              <div class="small-muted text-sm mb-3"><?= e(translate('pending_sellers_info', $lang, $translations)) ?></div>
              <div class="overflow-x-auto">
                <table class="w-full text-left text-sm border-collapse">
                  <thead>
                    <tr class="text-xs uppercase text-slate-400 border-b border-white/10">
                      <th class="p-3">ID</th>
                      <th class="p-3">Email</th>
                      <th class="p-3">Name</th>
                      <th class="p-3">Workspace</th>
                      <th class="p-3">Status</th>
                      <th class="p-3">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($pendingSellers as $pendingSeller): ?>
                      <tr class="border-b border-white/10">
                        <td class="p-3"><?= e($pendingSeller['id']) ?></td>
                        <td class="p-3"><?= e($pendingSeller['email']) ?></td>
                        <td class="p-3"><?= e($pendingSeller['name']) ?></td>
                        <td class="p-3"><?= e($pendingSeller['store_name'] ?: $pendingSeller['slug'] ?: '-') ?></td>
                        <td class="p-3"><?= e(translate('pending', $lang, $translations)) ?></td>
                        <td class="p-3">
                          <form method="post" class="inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="user_id" value="<?= e($pendingSeller['id']) ?>">
                            <button type="submit" name="admin_approve_seller" class="px-2 py-1 bg-emerald-600 rounded text-xs text-white"><?= e(translate('approve', $lang, $translations)) ?></button>
                          </form>
                        </td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            </div>
          <?php endif; ?>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm border-collapse">
              <thead>
                <tr class="text-xs uppercase text-slate-400 border-b border-white/10">
                  <th class="p-3">ID</th>
                  <th class="p-3"><?= e(translate('table_slug', $lang, $translations)) ?></th>
                  <th class="p-3"><?= e(translate('table_name', $lang, $translations)) ?></th>
                  <th class="p-3"><?= e(translate('stat_products', $lang, $translations)) ?></th>
                  <th class="p-3"><?= e(translate('table_actions', $lang, $translations)) ?></th>
                </tr>
              </thead>
              <tbody>
                <?php if (empty($adminWorkspaces)): ?>
                  <tr><td colspan="5" class="p-3 small-muted"><?= e(translate('no_workspaces', $lang, $translations)) ?></td></tr>
                <?php else: ?>
                  <?php foreach ($adminWorkspaces as $adminWorkspace): $productCount = productsCount($pdo, intval($adminWorkspace['id'])); ?>
                    <tr class="border-b border-white/10">
                      <td class="p-3"><?= e($adminWorkspace['id']) ?></td>
                      <td class="p-3"><?= e($adminWorkspace['slug']) ?></td>
                      <td class="p-3"><?= e($adminWorkspace['store_name'] ?: $adminWorkspace['name']) ?></td>
                      <td class="p-3"><?= e($productCount) ?></td>
                      <td class="p-3">
                        <div class="flex flex-wrap gap-2">
                          <a class="btn-ghost text-xs" href="?admin=1&lang=<?= urlencode($lang) ?>&shop=<?= urlencode($adminWorkspace['slug']) ?>"><?= e(translate('view', $lang, $translations)) ?></a>
                          <form method="post" class="inline" onsubmit="return confirm('<?= e(translate('delete_workspace_confirm', $lang, $translations)) ?>');">
                            <?= csrfField() ?>
                            <input type="hidden" name="workspace_id" value="<?= e($adminWorkspace['id']) ?>">
                            <button type="submit" name="admin_delete_workspace" class="text-xs text-rose-300"><?= e(translate('delete', $lang, $translations)) ?></button>
                          </form>
                        </div>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                <?php endif; ?>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    <?php endif; ?>

    <?php if (!$showAdmin): ?>
      <?php if (empty($workspaces)): ?>
        <div class="empty-state">
        <div class="font-semibold"><?= e(translate('empty_title', $lang, $translations)) ?></div>
        <div class="small-muted mt-2"><?= e(translate('empty_subtitle', $lang, $translations)) ?></div>
      </div>
    <?php else: ?>
      <div id="workspaces" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <?php foreach ($workspaces as $w):
          $phone = $w['phone'] ?: $defaultPhone;
          $logo = $w['logo'] ?: $defaultLogo;
          $count = productsCount($pdo, $w['id']);
        ?>
          <div class="card">
            <div class="flex items-start gap-3">
              <img src="<?= e($logo) ?>" alt="<?= e($w['store_name'] ?: $w['name']) ?>" class="logo-sm">
              <div class="flex-1">
                <div class="flex items-center justify-between">
                  <div>
                    <div class="font-semibold"><?= e($w['store_name'] ?: $w['name']) ?></div>
                    <div class="small-muted text-xs"><?= e($w['slug']) ?> • <?= sprintf(translate('products_count', $lang, $translations), $count) ?></div>
                  </div>
                  <div class="text-right">
                    <div class="small-muted text-xs"><?= e($phone) ?></div>
                  </div>
                </div>

                <div class="mt-3 flex items-center gap-2 flex-wrap">
                  <a class="px-3 py-2 bg-gradient-to-r from-indigo-600 to-cyan-500 hover:from-indigo-500 hover:to-cyan-400 text-white rounded-lg text-sm font-semibold shadow-md" href="?shop=<?= urlencode($w['slug']) ?>&lang=<?= urlencode($lang) ?>">🛍️ <?= e(translate('see_products', $lang, $translations)) ?></a>
                  <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="<?= e(whatsappLink($phone, 'Hello, I would like more information about ' . ($w['store_name'] ?: $w['name']) . '.')) ?>" target="_blank">💬 <?= e(translate('contact', $lang, $translations)) ?></a>
                </div>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>

    <?php if ($selectedProduct && $selectedWorkspace): ?>
      <section class="card mb-6">
        <div class="flex items-center justify-between mb-3">
          <div class="font-semibold"><?= e(translate('product_details', $lang, $translations)) ?></div>
          <a href="?shop=<?= urlencode($selectedWorkspace['slug']) ?>&lang=<?= urlencode($lang) ?>" class="text-sm link-muted">← <?= e(translate('back_to_store', $lang, $translations)) ?></a>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <?php if (!empty($galleryImages)): ?>
              <img id="productMainImage" src="<?= e($galleryImages[0]) ?>" alt="<?= e($selectedProduct['name']) ?>" class="w-full h-80 object-cover rounded-lg border border-white/10 cursor-zoom-in">
              <div class="flex flex-wrap gap-2 mt-3">
                <?php foreach ($galleryImages as $index => $image): ?>
                  <img class="gallery-thumb <?= $index === 0 ? 'active' : '' ?>" src="<?= e($image) ?>" alt="<?= e($selectedProduct['name']) ?> preview" data-image="<?= e($image) ?>" data-index="<?= $index ?>">
                <?php endforeach; ?>
              </div>
            <?php elseif (!empty($selectedProduct['image_url'])): ?>
              <img src="<?= e($selectedProduct['image_url']) ?>" alt="<?= e($selectedProduct['name']) ?>" class="w-full h-80 object-cover rounded-lg border border-white/10">
            <?php else: ?>
              <div class="w-full h-80 rounded-lg border border-dashed border-white/10 flex items-center justify-center bg-black/20 text-sm text-slate-300"><?= e(translate('no_image', $lang, $translations)) ?></div>
            <?php endif; ?>
          </div>
          <div>
            <div class="text-xl font-semibold"><?= e($selectedProduct['name']) ?></div>
            <div class="small-muted text-sm mt-1"><?= e(($selectedProduct['parent_category_name'] ? $selectedProduct['parent_category_name'] . ' / ' : '') . ($selectedProduct['category_name'] ?? '')) ?> • <?= e(translate('sku_label', $lang, $translations)) ?>: <?= e($selectedProduct['sku'] ?: translate('na', $lang, $translations)) ?></div>
            <div class="text-2xl font-semibold mt-3"><?= e(number_format(floatval($selectedProduct['price']), 0)) ?> IQD</div>
            <?php if (!empty($selectedProduct['brand'])): ?><div class="small-muted text-sm mt-2"><?= e(translate('brand_label', $lang, $translations)) ?>: <?= e($selectedProduct['brand']) ?></div><?php endif; ?>
            <?php if (!empty($selectedProduct['stock_status'])): ?><div class="small-muted text-sm mt-2"><?= e(translate('availability', $lang, $translations)) ?>: <?= e(translateStockStatus((string) $selectedProduct['stock_status'], $lang, $translations)) ?></div><?php endif; ?>
            <?php if (!empty($selectedProduct['description'])): ?><div class="small-muted mt-3"><?= e($selectedProduct['description']) ?></div><?php endif; ?>
            <?php if (!empty($selectedProduct['tags'])): ?>
              <div class="flex flex-wrap gap-1 mt-3">
                <?php foreach (parseTags((string) $selectedProduct['tags']) as $tag): ?>
                  <span class="rounded-full bg-white/10 px-2 py-0.5 text-[10px] uppercase tracking-[0.2em] text-slate-300"><?= e($tag) ?></span>
                <?php endforeach; ?>
              </div>
            <?php endif; ?>
            <div class="mt-4 flex flex-wrap gap-2">
              <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="<?= e(whatsappLink($selectedWorkspace['phone'] ?: $defaultPhone, 'Hello, I would like more information about ' . $selectedProduct['name'] . '.')) ?>" target="_blank" rel="noopener noreferrer">💬 <?= e(translate('contact_store', $lang, $translations)) ?></a>
            </div>
            <?php $productShareUrl = shareUrl('index.php?shop=' . urlencode($selectedWorkspace['slug']) . '&lang=' . urlencode($lang) . '&product=' . intval($selectedProduct['id'])); ?>
            <div class="mt-3 flex flex-wrap gap-2">
              <a class="text-sm link-muted" href="https://www.facebook.com/sharer/sharer.php?u=<?= rawurlencode($productShareUrl) ?>" target="_blank" rel="noopener noreferrer">📣 <?= e(translate('share_product', $lang, $translations)) ?></a>
              <a class="text-sm link-muted" href="https://wa.me/?text=<?= rawurlencode('Check this product: ' . $productShareUrl) ?>" target="_blank" rel="noopener noreferrer">💬 <?= e(translate('share_whatsapp', $lang, $translations)) ?></a>
              <a class="text-sm link-muted" href="<?= e($productShareUrl) ?>" target="_blank" rel="noopener noreferrer">🔗 <?= e(translate('product_link', $lang, $translations)) ?></a>
            </div>
            <div class="mt-3 rounded-lg border border-white/10 p-2 inline-block">
              <img src="<?= e(qrDataUrl($productShareUrl)) ?>" alt="Product QR" class="w-24 h-24 rounded-lg border border-white/10 bg-white p-1">
            </div>
          </div>
        </div>
      </section>
    <?php endif; ?>

    <!-- If seller logged in, show simple dashboard -->
    <?php if ($auth && $auth['type'] === 'seller'): 
      if ($showMyShop && $sellerWorkspace):
        $profileProducts = productsByWorkspace($pdo, intval($sellerWorkspace['id']));
      endif;
      $wId = intval($auth['workspace_id']);
      $editProductId = isset($_GET['edit_product']) ? intval($_GET['edit_product']) : 0;
      $editingProduct = null;
      if ($editProductId > 0) {
          $editingProduct = productById($pdo, $wId, $editProductId);
      }
      ensureSellerSubscription($pdo, intval($auth['id']), $wId);
      $sellerSubscription = getSellerSubscription($pdo, intval($auth['id']));
      $paymentHistory = $pdo->prepare("SELECT * FROM payments WHERE workspace_id = ? ORDER BY id DESC LIMIT 10");
      $paymentHistory->execute([$wId]);
      $paymentHistory = $paymentHistory->fetchAll();
      $cats = $pdo->prepare("SELECT * FROM categories WHERE workspace_id = ? ORDER BY id ASC");
      $cats->execute([$wId]);
      $cats = $cats->fetchAll();
      $prods = $pdo->prepare("SELECT p.*, c.name AS category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.workspace_id = ? ORDER BY p.id DESC");
      $prods->execute([$wId]);
      $prods = $prods->fetchAll();
    ?>
      <?php if ($showMyShop && $sellerWorkspace): ?>
        <section class="mt-6 p-4 bg-white/5 border border-white/10 rounded">
          <div class="flex flex-col xl:flex-row gap-4">
            <div class="flex-1 space-y-4">
              <div class="rounded-2xl overflow-hidden border border-white/10 bg-slate-900/60">
                <?php if (!empty($sellerWorkspace['cover_image'])): ?>
                  <img src="<?= e($sellerWorkspace['cover_image']) ?>" alt="<?= e($sellerWorkspace['store_name'] ?: $sellerWorkspace['name']) ?>" class="w-full h-56 object-cover">
                <?php else: ?>
                  <div class="w-full h-56 bg-slate-800 flex items-center justify-center text-slate-400"><?= e(translate('cover_preview', $lang, $translations)) ?></div>
                <?php endif; ?>
                <div class="p-5">
                  <div class="flex items-center gap-4">
                    <img src="<?= e($sellerWorkspace['logo'] ?: $defaultLogo) ?>" alt="<?= e($sellerWorkspace['store_name'] ?: $sellerWorkspace['name']) ?>" class="w-20 h-20 rounded-2xl object-cover border border-white/10">
                    <div>
                      <div class="text-2xl font-semibold"><?= e($sellerWorkspace['store_name'] ?: $sellerWorkspace['name']) ?></div>
                      <div class="small-muted mt-1"><?= e($sellerWorkspace['description'] ?: translate('shop_desc_preview', $lang, $translations)) ?></div>
                    </div>
                  </div>
                  <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <?php if (!empty($sellerWorkspace['address'])): ?><div class="pill">📍 <?= e($sellerWorkspace['address']) ?></div><?php endif; ?>
                    <?php if (!empty($sellerWorkspace['phone'])): ?><div class="pill">📞 <?= e($sellerWorkspace['phone']) ?></div><?php endif; ?>
                    <?php if (!empty($sellerWorkspace['business_hours'])): ?><div class="pill">🕒 <?= e($sellerWorkspace['business_hours']) ?></div><?php endif; ?>
                    <?php if (!empty($sellerWorkspace['website'])): ?><div class="pill">🔗 <a href="<?= e($sellerWorkspace['website']) ?>" target="_blank" rel="noopener noreferrer"><?= e($sellerWorkspace['website']) ?></a></div><?php endif; ?>
                  </div>
                  <?php if (!empty($sellerWorkspace['social_links'])): ?><div class="mt-4 small-muted text-sm"><?= e(translate('social_label', $lang, $translations)) ?>: <?= e($sellerWorkspace['social_links']) ?></div><?php endif; ?>
                </div>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="card">
                  <div class="font-semibold mb-2"><?= e(translate('profile_preview', $lang, $translations)) ?></div>
                  <div class="space-y-2 text-sm small-muted">
                    <div><strong><?= e(translate('shop_name_label', $lang, $translations)) ?>:</strong> <?= e($sellerWorkspace['store_name'] ?: $sellerWorkspace['name']) ?></div>
                    <div><strong><?= e(translate('business_name_label', $lang, $translations)) ?>:</strong> <?= e($sellerWorkspace['name']) ?></div>
                    <div><strong><?= e(translate('description_label', $lang, $translations)) ?>:</strong> <?= e($sellerWorkspace['description'] ?: translate('not_set', $lang, $translations)) ?></div>
                    <div><strong><?= e(translate('website_label', $lang, $translations)) ?>:</strong> <?= e($sellerWorkspace['website'] ?: translate('not_set', $lang, $translations)) ?></div>
                    <div><strong><?= e(translate('address_label', $lang, $translations)) ?>:</strong> <?= e($sellerWorkspace['address'] ?: translate('not_set', $lang, $translations)) ?></div>
                    <div><strong><?= e(translate('hours_label', $lang, $translations)) ?>:</strong> <?= e($sellerWorkspace['business_hours'] ?: translate('not_set', $lang, $translations)) ?></div>
                    <div><strong><?= e(translate('social_links_label', $lang, $translations)) ?>:</strong> <?= e($sellerWorkspace['social_links'] ?: translate('not_set', $lang, $translations)) ?></div>
                  </div>
                </div>
                <div class="card">
                  <div class="font-semibold mb-2"><?= e(translate('shop_snapshot', $lang, $translations)) ?></div>
                  <div class="small-muted text-sm"><?= e(translate('shop_snapshot_desc', $lang, $translations)) ?></div>
                  <div class="mt-3 grid grid-cols-1 gap-3">
                    <?php foreach (array_slice($profileProducts ?? [], 0, 4) as $product): ?>
                      <div class="border border-white/10 rounded-lg p-3">
                        <div class="font-semibold text-sm"><?= e($product['name']) ?></div>
                        <div class="small-muted text-xs"><?= e($product['category_name'] ?? translate('uncategorized', $lang, $translations)) ?></div>
                        <div class="text-sm mt-2"><?= e(number_format(floatval($product['price']),0)) ?> IQD</div>
                      </div>
                    <?php endforeach; ?>
                    <?php if (empty($profileProducts)): ?><div class="small-muted"><?= e(translate('add_products_feed', $lang, $translations)) ?></div><?php endif; ?>
                  </div>
                </div>
              </div>
            </div>
            <div class="w-full xl:w-[360px] rounded-2xl border border-white/10 bg-slate-900/60 p-4" id="sellerSettings">
              <div class="font-semibold mb-3"><?= e(translate('improve_profile', $lang, $translations)) ?></div>
              <form method="post" enctype="multipart/form-data" class="space-y-3" id="shopProfileForm">
                <?= csrfField() ?>
                <div class="grid grid-cols-1 gap-3">
                  <input name="business_name" class="input-dark w-full" value="<?= e($sellerWorkspace['name'] ?? $auth['name']) ?>" placeholder="<?= e(translate('business_name_label', $lang, $translations)) ?>">
                  <input name="store_name" class="input-dark w-full" value="<?= e($sellerWorkspace['store_name'] ?? $auth['name']) ?>" placeholder="<?= e(translate('shop_name_label', $lang, $translations)) ?>">
                  <input name="store_website" class="input-dark w-full" value="<?= e($sellerWorkspace['website'] ?? '') ?>" placeholder="<?= e(translate('website_label', $lang, $translations)) ?>">
                  <label class="text-xs small-muted"><?= e(translate('profile_theme', $lang, $translations)) ?></label>
                  <div class="theme-swatch-grid">
                    <?php
                      $themes = [
                        ['#0ea5a4','#1d4ed8'],['#38bdf8','#0f172a'],['#f97316','#111827'],['#a855f7','#0f172a'],
                        ['#facc15','#0f172a'],['#ec4899','#111827'],['#22c55e','#134e4a'],['#e11d48','#111827'],
                        ['#2563eb','#e0f2fe'],['#16a34a','#d1fae5'],['#fb7185','#ffffff'],['#f59e0b','#fef3c7'],
                        ['#0ea5a4','#e0f2fe'],['#6366f1','#eef2ff'],['#ef4444','#fef2f2'],['#14b8a6','#cffafe'],
                        ['#8b5cf6','#ede9fe'],['#ec4899','#fdf2f8'],['#1d4ed8','#dbeafe'],['#7c3aed','#ede9fe'],
                      ];
                      $currentPrimary = $sellerWorkspace['primary_color'] ?: $sellerWorkspace['theme_color'] ?: '#0ea5a4';
                      $currentSecondary = $sellerWorkspace['secondary_color'] ?: '#111827';
                    ?>
                    <?php foreach ($themes as $t): $active = ($t[0] === $currentPrimary && $t[1] === $currentSecondary) ? 'selected' : ''; ?>
                      <button type="button" class="theme-swatch <?= $active ?>" data-primary="<?= e($t[0]) ?>" data-secondary="<?= e($t[1]) ?>" style="background: linear-gradient(135deg, <?= e($t[0]) ?>, <?= e($t[1]) ?>);"></button>
                    <?php endforeach; ?>
                  </div>
                  <div class="grid grid-cols-2 gap-3">
                    <label class="text-xs small-muted"><?= e(translate('primary_color', $lang, $translations)) ?></label>
                    <label class="text-xs small-muted"><?= e(translate('secondary_color', $lang, $translations)) ?></label>
                    <input name="store_primary_color" id="storePrimaryColor" type="color" class="input-dark w-full h-12" value="<?= e($currentPrimary) ?>">
                    <input name="store_secondary_color" id="storeSecondaryColor" type="color" class="input-dark w-full h-12" value="<?= e($currentSecondary) ?>">
                  </div>
                  <input name="store_logo_file" type="file" accept="image/*" class="input-dark w-full">
                  <input name="store_logo" class="input-dark w-full" value="<?= e($sellerWorkspace['logo'] ?? '') ?>" placeholder="<?= e(translate('logo_or_url', $lang, $translations)) ?>">
                  <input name="store_cover" class="input-dark w-full" value="<?= e($sellerWorkspace['cover_image'] ?? '') ?>" placeholder="<?= e(translate('cover_url', $lang, $translations)) ?>">
                  <textarea name="store_description" class="input-dark w-full" rows="3" placeholder="<?= e(translate('shop_description', $lang, $translations)) ?>"> <?= e($sellerWorkspace['description'] ?? '') ?></textarea>
                  <input name="store_address" class="input-dark w-full" value="<?= e($sellerWorkspace['address'] ?? '') ?>" placeholder="<?= e(translate('address_label', $lang, $translations)) ?>">
                  <input name="store_phone" class="input-dark w-full" value="<?= e($sellerWorkspace['phone'] ?? '') ?>" placeholder="<?= e(translate('phone_label', $lang, $translations)) ?>">
                  <input name="store_hours" class="input-dark w-full" value="<?= e($sellerWorkspace['business_hours'] ?? '') ?>" placeholder="<?= e(translate('hours_label', $lang, $translations)) ?>">
                  <input name="store_social" class="input-dark w-full" value="<?= e($sellerWorkspace['social_links'] ?? '') ?>" placeholder="<?= e(translate('social_links_label', $lang, $translations)) ?>">
                  <input name="store_url" class="input-dark w-full" value="<?= e($sellerWorkspace['slug'] ?? '') ?>" placeholder="<?= e(translate('custom_url', $lang, $translations)) ?>">
                </div>
                <button name="seller_update_profile" class="px-3 py-2 bg-cyan-600 rounded text-sm w-full"><?= e(translate('save_shop_profile', $lang, $translations)) ?></button>
              </form>
              <?php $publicShopUrl = shareUrl('index.php?shop=' . urlencode($sellerWorkspace['slug']) . '&lang=' . urlencode($lang)); ?>
              <div class="card mt-4">
                <div class="font-semibold mb-3"><?= e(translate('share_profile', $lang, $translations)) ?></div>
                <div class="small-muted text-sm break-words mb-3"><?= e(translate('public_link', $lang, $translations)) ?>:</div>
                <div class="flex gap-2 items-center mb-3">
                  <input id="publicProfileLink" type="text" readonly class="input-dark flex-1" value="<?= e($publicShopUrl) ?>">
                  <button id="copyProfileLink" type="button" class="px-3 py-2 bg-emerald-600 rounded text-sm" data-copy-label="<?= e(translate('copy', $lang, $translations)) ?>" data-copied-label="<?= e(translate('copied', $lang, $translations)) ?>"><?= e(translate('copy', $lang, $translations)) ?></button>
                </div>
                <img id="shopProfileQr" src="<?= e(qrDataUrl($publicShopUrl)) ?>" alt="Shop QR code" class="w-full rounded-lg border border-white/10 bg-white p-2 mb-3">
                <div class="flex gap-2">
                  <button id="downloadQrButton" type="button" class="px-3 py-2 bg-cyan-600 rounded text-sm flex-1"><?= e(translate('download_qr', $lang, $translations)) ?></button>
                  <a href="https://www.facebook.com/sharer/sharer.php?u=<?= rawurlencode($publicShopUrl) ?>" target="_blank" rel="noopener noreferrer" class="px-3 py-2 bg-slate-700 rounded text-sm flex-1 text-center"><?= e(translate('share_btn', $lang, $translations)) ?></a>
                </div>
              </div>
              <div class="card mt-4">
                <div class="font-semibold mb-3"><?= e(translate('quick_shortcuts', $lang, $translations)) ?></div>
                <div class="grid grid-cols-2 gap-2">
                  <a href="#sellerProducts" class="btn-ghost text-center py-3"><?= e(translate('products_nav', $lang, $translations)) ?></a>
                  <a href="#sellerCategories" class="btn-ghost text-center py-3"><?= e(translate('categories_nav', $lang, $translations)) ?></a>
                  <a href="#sellerAnalytics" class="btn-ghost text-center py-3"><?= e(translate('analytics_nav', $lang, $translations)) ?></a>
                  <a href="#sellerSettings" class="btn-ghost text-center py-3"><?= e(translate('settings_nav', $lang, $translations)) ?></a>
                  <button type="button" class="btn-ghost text-center py-3" disabled><?= e(translate('orders_nav', $lang, $translations)) ?></button>
                  <a href="<?= e($publicShopUrl) ?>" target="_blank" class="btn-ghost text-center py-3"><?= e(translate('public_profile', $lang, $translations)) ?></a>
                </div>
              </div>
              <div class="card mt-4 shop-preview-card p-4 text-white" id="shopPreviewBox" style="--preview-primary: <?= e($currentPrimary) ?>; --preview-secondary: <?= e($currentSecondary) ?>;">
                <div class="font-semibold mb-3"><?= e(translate('preview_below', $lang, $translations)) ?></div>
                <div class="text-sm opacity-90">
                  <div><?= e(translate('shop_name_label', $lang, $translations)) ?>: <?= e($sellerWorkspace['store_name'] ?: $sellerWorkspace['name']) ?></div>
                  <div><?= e(translate('brand_color_hint', $lang, $translations)) ?></div>
                  <div><?= e(translate('color_change_hint', $lang, $translations)) ?></div>
                </div>
              </div>
            </div>
          </div>
        </section>
      <?php endif; ?>
      <section class="mt-4 p-3 bg-[#071827] border border-white/5 rounded-lg">
        <div class="dashboard-header">
          <div>
            <div class="title"><?= e(translate('seller_dashboard', $lang, $translations)) ?> — <?= e($auth['name']) ?></div>
            <div class="small-muted mt-1"><?= e(translate('workspace_id', $lang, $translations)) ?>: <?= $wId ?></div>
          </div>
          <div class="dashboard-actions">
            <a href="?my_shop=1&lang=<?= urlencode($lang) ?>" class="btn-ghost"><?= e(translate('refresh_dashboard', $lang, $translations)) ?></a>
            <a href="<?= e($publicShopUrl) ?>" target="_blank" class="btn-ghost"><?= e(translate('preview_public_shop', $lang, $translations)) ?></a>
          </div>
        </div>

        <div class="dashboard-stat-grid mb-3">
          <div class="dashboard-stat"><span class="label"><?= e(translate('total_visitors', $lang, $translations)) ?></span><span class="value"><?= e($analytics['total_visitors'] ?? 0) ?></span></div>
          <div class="dashboard-stat"><span class="label"><?= e(translate('product_views_label', $lang, $translations)) ?></span><span class="value"><?= e($analytics['product_views'] ?? 0) ?></span></div>
          <div class="dashboard-stat"><span class="label"><?= e(translate('daily_visitors', $lang, $translations)) ?></span><span class="value"><?= e($analytics['daily_visitors'] ?? 0) ?></span></div>
          <div class="dashboard-stat"><span class="label"><?= e(translate('monthly_visitors', $lang, $translations)) ?></span><span class="value"><?= e($analytics['monthly_visitors'] ?? 0) ?></span></div>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div class="dashboard-panel">
            <div class="font-semibold mb-1.5 text-sm"><?= e(translate('top_viewed', $lang, $translations)) ?></div>
            <?php if (empty($analytics['top_products'])): ?><div class="small-muted"><?= e(translate('no_product_views', $lang, $translations)) ?></div><?php else: ?><div class="space-y-1.5"><?php foreach ($analytics['top_products'] as $row): $product = productById($pdo, $wId, intval($row['product_id'])); ?><div class="flex items-center justify-between"><div class="text-sm"><?= e($product['name'] ?? sprintf(translate('product_num', $lang, $translations), $row['product_id'])) ?></div><div class="small-muted text-xs"><?= e(sprintf(translate('views_count', $lang, $translations), $row['views'])) ?></div></div><?php endforeach; ?></div><?php endif; ?>
          </div>
          <div class="dashboard-panel">
            <div class="font-semibold mb-1.5 text-sm"><?= e(translate('popular_categories_analytics', $lang, $translations)) ?></div>
            <?php if (empty($analytics['categories'])): ?><div class="small-muted"><?= e(translate('no_category_activity', $lang, $translations)) ?></div><?php else: ?><div class="space-y-1.5"><?php foreach ($analytics['categories'] as $row): ?><div class="flex items-center justify-between"><div class="text-sm"><?= e($row['category_name']) ?></div><div class="small-muted text-xs"><?= e(sprintf(translate('views_count', $lang, $translations), $row['c'])) ?></div></div><?php endforeach; ?></div><?php endif; ?>
          </div>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-3">
          <div class="dashboard-panel">
            <div class="font-semibold mb-1.5 text-sm"><?= e(translate('device_types', $lang, $translations)) ?></div>
            <?php if (empty($analytics['devices'])): ?><div class="small-muted"><?= e(translate('no_device_data', $lang, $translations)) ?></div><?php else: ?><div class="space-y-1.5"><?php foreach ($analytics['devices'] as $row): ?><div class="flex items-center justify-between"><div class="text-sm"><?= e($row['device_type']) ?></div><div class="small-muted text-xs"><?= e(sprintf(translate('visits_count', $lang, $translations), $row['c'])) ?></div></div><?php endforeach; ?></div><?php endif; ?>
          </div>
          <div class="dashboard-panel">
            <div class="font-semibold mb-1.5 text-sm"><?= e(translate('visitor_locations', $lang, $translations)) ?></div>
            <?php if (empty($analytics['locations'])): ?><div class="small-muted"><?= e(translate('no_location_data', $lang, $translations)) ?></div><?php else: ?><div class="space-y-1.5"><?php foreach ($analytics['locations'] as $row): ?><div class="flex items-center justify-between"><div class="text-sm"><?= e(($row['city'] ?: translate('unknown', $lang, $translations)) . ', ' . ($row['country'] ?: translate('unknown', $lang, $translations))) ?></div><div class="small-muted text-xs"><?= e(sprintf(translate('visits_count', $lang, $translations), $row['c'])) ?></div></div><?php endforeach; ?></div><?php endif; ?>
          </div>
        </div>

        <div class="grid grid-cols-1 xl:grid-cols-2 gap-3 mt-3">
          <div class="card dashboard-card xl:col-span-2" id="sellerSales">
            <div class="font-medium mb-2 text-sm"><?= e(translate('sales_overview', $lang, $translations)) ?></div>
            <?php if (!empty($sales_message)): ?><div class="small-muted mb-2 text-emerald-300"><?= e(translateMessage($sales_message, $lang, $translations)) ?></div><?php endif; ?>
            <div class="dashboard-stat-grid mb-3">
              <div class="dashboard-stat"><span class="label"><?= e(translate('lifetime_revenue', $lang, $translations)) ?></span><span class="value"><?= e(number_format($salesSummary['revenue'], 0)) ?> IQD</span></div>
              <div class="dashboard-stat"><span class="label"><?= e(translate('sales_records', $lang, $translations)) ?></span><span class="value"><?= e($salesSummary['orders']) ?></span></div>
              <div class="dashboard-stat"><span class="label"><?= e(translate('units_sold', $lang, $translations)) ?></span><span class="value"><?= e($salesSummary['units']) ?></span></div>
              <div class="dashboard-stat"><span class="label"><?= e(translate('this_month', $lang, $translations)) ?></span><span class="value"><?= e(number_format($salesSummary['month_revenue'], 0)) ?> IQD</span></div>
            </div>
            <form method="get" class="dashboard-panel mb-3">
              <input type="hidden" name="my_shop" value="1">
              <input type="hidden" name="lang" value="<?= e($lang) ?>">
              <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div>
                  <label class="text-xs small-muted"><?= e(translate('from_date', $lang, $translations)) ?></label>
                  <input name="sale_from" type="date" class="input-dark w-full" value="<?= e($salesFrom) ?>">
                </div>
                <div>
                  <label class="text-xs small-muted"><?= e(translate('to_date', $lang, $translations)) ?></label>
                  <input name="sale_to" type="date" class="input-dark w-full" value="<?= e($salesTo) ?>">
                </div>
                <div>
                  <label class="text-xs small-muted"><?= e(translate('sales_search', $lang, $translations)) ?></label>
                  <input name="sale_q" type="search" class="input-dark w-full" placeholder="<?= e(translate('sales_search_ph', $lang, $translations)) ?>" value="<?= e($salesQuery) ?>">
                </div>
              </div>
              <div class="flex flex-wrap gap-2 mt-2">
                <button class="px-3 py-2 bg-cyan-600 rounded text-sm"><?= e(translate('filter', $lang, $translations)) ?></button>
                <a href="?my_shop=1&lang=<?= urlencode($lang) ?>" class="px-3 py-2 border border-white/10 rounded text-sm"><?= e(translate('reset', $lang, $translations)) ?></a>
              </div>
            </form>
            <div class="grid grid-cols-1 lg:grid-cols-4 gap-2 mb-3">
              <div class="rounded-lg border border-white/10 p-2">
                <div class="small-muted text-xs"><?= e(translate('today', $lang, $translations)) ?></div>
                <div class="text-lg font-semibold"><?= e(number_format($salesSummary['today_revenue'], 0)) ?> IQD</div>
                <div class="mt-1"><?= renderGrowthBadge($salesSummary['today_change'] ?? null, translate('vs_yesterday', $lang, $translations), translate('no_prior_data', $lang, $translations)) ?></div>
              </div>
              <div class="rounded-lg border border-white/10 p-2">
                <div class="small-muted text-xs"><?= e(translate('current_week', $lang, $translations)) ?></div>
                <div class="text-lg font-semibold"><?= e(number_format($salesSummary['week_revenue'], 0)) ?> IQD</div>
                <div class="mt-1"><?= renderGrowthBadge($salesSummary['week_change'] ?? null, translate('vs_last_week', $lang, $translations), translate('no_prior_data', $lang, $translations)) ?></div>
              </div>
              <div class="rounded-lg border border-white/10 p-2">
                <div class="small-muted text-xs"><?= e(translate('current_month', $lang, $translations)) ?></div>
                <div class="text-lg font-semibold"><?= e(number_format($salesSummary['month_revenue'], 0)) ?> IQD</div>
                <div class="mt-1"><?= renderGrowthBadge($salesSummary['month_change'] ?? null, translate('vs_last_month', $lang, $translations), translate('no_prior_data', $lang, $translations)) ?></div>
              </div>
              <div class="rounded-lg border border-white/10 p-2">
                <div class="small-muted text-xs"><?= e(translate('current_year', $lang, $translations)) ?></div>
                <div class="text-lg font-semibold"><?= e(number_format($salesSummary['year_revenue'], 0)) ?> IQD</div>
                <div class="mt-1"><?= renderGrowthBadge($salesSummary['year_change'] ?? null, translate('vs_last_year', $lang, $translations), translate('no_prior_data', $lang, $translations)) ?></div>
              </div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-3 mb-3">
              <div class="rounded-lg border border-white/10 p-2">
                <div class="font-semibold mb-1.5 text-sm"><?= e(translate('best_selling', $lang, $translations)) ?></div>
                <?php if (empty($salesSummary['best_products'])): ?><div class="small-muted"><?= e(translate('no_sales_yet', $lang, $translations)) ?></div><?php else: ?><div class="space-y-1.5"><?php foreach ($salesSummary['best_products'] as $row): ?><div class="flex items-center justify-between"><div class="text-sm"><?= e($row['product_name']) ?></div><div class="small-muted text-xs"><?= e($row['qty']) ?> <?= e(translate('pcs', $lang, $translations)) ?> • <?= e(number_format((float)$row['revenue'], 0)) ?> IQD</div></div><?php endforeach; ?></div><?php endif; ?>
              </div>
              <div class="rounded-lg border border-white/10 p-2">
                <div class="font-semibold mb-1.5 text-sm"><?= e(translate('category_revenue', $lang, $translations)) ?></div>
                <?php if (empty($salesSummary['category_revenue'])): ?><div class="small-muted"><?= e(translate('no_category_revenue', $lang, $translations)) ?></div><?php else: ?><div class="space-y-1.5"><?php foreach ($salesSummary['category_revenue'] as $row): ?><div class="flex items-center justify-between"><div class="text-sm"><?= e($row['category_name']) ?></div><div class="small-muted text-xs"><?= e(number_format((float)$row['revenue'], 0)) ?> IQD</div></div><?php endforeach; ?></div><?php endif; ?>
              </div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-3 mb-3">
              <div class="rounded-lg border border-white/10 p-2">
                <div class="font-semibold mb-1.5 text-sm"><?= e(translate('revenue_30_days', $lang, $translations)) ?></div>
                <canvas id="salesDailyChart" height="140"></canvas>
              </div>
              <div class="rounded-lg border border-white/10 p-2">
                <div class="font-semibold mb-1.5 text-sm"><?= e(translate('revenue_monthly', $lang, $translations)) ?></div>
                <canvas id="salesMonthlyChart" height="140"></canvas>
              </div>
            </div>
            <div class="grid grid-cols-1 xl:grid-cols-[0.75fr_1.25fr] gap-3">
              <div class="rounded-lg border border-white/10 p-3">
                <div class="font-semibold mb-1.5 text-sm"><?= e(translate('record_sale', $lang, $translations)) ?></div>
                <form method="post" class="space-y-2">
                  <?= csrfField() ?>
                  <div>
                    <label class="text-xs small-muted"><?= e(translate('product_select', $lang, $translations)) ?></label>
                    <select name="sale_product_id" class="input-dark w-full">
                      <option value=""><?= e(translate('general_item', $lang, $translations)) ?></option>
                      <?php foreach ($prods as $prod): ?><option value="<?= e($prod['id']) ?>" <?= ($prod['id'] === intval($_POST['sale_product_id'] ?? 0) ? 'selected' : '') ?>><?= e($prod['name']) ?> <?= e($prod['sku'] ? '(' . $prod['sku'] . ')' : '') ?></option><?php endforeach; ?>
                    </select>
                  </div>
                  <div class="grid grid-cols-2 gap-2">
                    <div>
                      <label class="text-xs small-muted"><?= e(translate('quantity', $lang, $translations)) ?></label>
                      <input type="number" name="sale_quantity" min="1" value="<?= e(intval($_POST['sale_quantity'] ?? 1)) ?>" class="input-dark w-full">
                    </div>
                    <div>
                      <label class="text-xs small-muted"><?= e(translate('unit_price', $lang, $translations)) ?></label>
                      <input type="number" name="sale_unit_price" step="1" min="0" value="<?= e(floatval($_POST['sale_unit_price'] ?? '0')) ?>" class="input-dark w-full">
                    </div>
                  </div>
                  <div>
                    <label class="text-xs small-muted"><?= e(translate('sale_date', $lang, $translations)) ?></label>
                    <input type="date" name="sale_date" class="input-dark w-full" value="<?= e($_POST['sale_date'] ?? date('Y-m-d')) ?>">
                  </div>
                  <div>
                    <label class="text-xs small-muted"><?= e(translate('notes', $lang, $translations)) ?></label>
                    <textarea name="sale_notes" class="input-dark w-full" rows="2" placeholder="<?= e(translate('notes_ph', $lang, $translations)) ?>"><?= e($_POST['sale_notes'] ?? '') ?></textarea>
                  </div>
                  <button name="seller_add_sale" class="px-3 py-2 bg-emerald-600 rounded text-sm w-full"><?= e(translate('record_sale_btn', $lang, $translations)) ?></button>
                </form>
              </div>
              <div class="rounded-lg border border-white/10 p-3">
                <div class="font-semibold mb-1.5 text-sm"><?= e(translate('recent_sales', $lang, $translations)) ?></div>
                <?php if (empty($salesRecords)): ?><div class="small-muted"><?= e(translate('no_sales_period', $lang, $translations)) ?></div><?php else: ?><div class="space-y-2 overflow-hidden">
                  <?php foreach ($salesRecords as $sale): ?><div class="border border-white/5 rounded-lg p-2">
                    <div class="flex items-start justify-between gap-2">
                      <div>
                        <div class="font-semibold text-sm"><?= e($sale['product_name'] ?: translate('general_item', $lang, $translations)) ?></div>
                        <div class="small-muted text-xs"><?= e($sale['category_name'] ?: translate('no_category', $lang, $translations)) ?> • <?= e($sale['sku'] ?: translate('na', $lang, $translations)) ?></div>
                      </div>
                      <div class="text-right">
                        <div class="text-sm font-semibold"><?= e(number_format((float)$sale['total_price'], 0)) ?> IQD</div>
                        <div class="small-muted text-xs"><?= e($sale['sale_date']) ?></div>
                      </div>
                    </div>
                    <div class="mt-2 small-muted text-xs"><?= e(translate('qty_label', $lang, $translations)) ?>: <?= e($sale['quantity']) ?> × <?= e(number_format((float)$sale['unit_price'], 0)) ?> IQD</div>
                    <?php if (!empty($sale['notes'])): ?><div class="mt-2 small-muted text-xs"><?= e(translate('notes_label', $lang, $translations)) ?>: <?= e($sale['notes']) ?></div><?php endif; ?>
                    <form method="post" class="mt-3 inline">
                      <?= csrfField() ?>
                      <input type="hidden" name="sale_id" value="<?= e($sale['id']) ?>">
                      <button name="seller_delete_sale" class="text-xs text-rose-300"><?= e(translate('delete', $lang, $translations)) ?></button>
                    </form>
                  </div><?php endforeach; ?></div><?php endif; ?>
              </div>
            </div>
          </div>

          <div class="card dashboard-card xl:col-span-2">
            <div class="font-medium mb-2 text-sm"><?= e(translate('business_management', $lang, $translations)) ?></div>
            <?php if (!empty($subscription_message)): ?><div class="small-muted mb-2 text-emerald-300"><?= e(translateMessage($subscription_message, $lang, $translations)) ?></div><?php endif; ?>
            <div class="grid grid-cols-1 lg:grid-cols-[0.9fr_1.1fr] gap-3">
              <div class="rounded-lg border border-white/10 p-3">
                <div class="font-semibold mb-2"><?= e(translate('store_health', $lang, $translations)) ?></div>
                <div class="small-muted text-sm"><?= e(translate('store_health_desc', $lang, $translations)) ?></div>
              </div>
              <div class="grid grid-cols-1 gap-3">
                <div class="rounded-lg border border-white/10 p-3">
                  <div class="font-semibold text-sm"><?= e(translate('recent_activity', $lang, $translations)) ?></div>
                  <div class="small-muted text-xs"><?= e(translate('recent_activity_desc', $lang, $translations)) ?></div>
                </div>
              </div>
            </div>
          </div>

          <div class="card dashboard-card" id="sellerProducts">
            <div id="sellerCategories"></div>
            <div class="font-medium mb-2 text-sm"><?= $editingProduct ? e(translate('edit_product', $lang, $translations)) : e(translate('add_product', $lang, $translations)) ?></div>
            <?php if (!empty($product_message)): ?><div class="small-muted mb-2"><?= e(translateMessage($product_message, $lang, $translations)) ?></div><?php endif; ?>
            <form method="post" enctype="multipart/form-data" class="space-y-2">
              <?= csrfField() ?>
              <?php if ($editingProduct): ?>
                <input type="hidden" name="product_id" value="<?= e($editingProduct['id']) ?>">
              <?php endif; ?>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label class="text-xs small-muted"><?= e(translate('category', $lang, $translations)) ?></label>
                  <input name="prod_category" class="input-dark w-full mb-2" placeholder="<?= e(translate('category_placeholder', $lang, $translations)) ?>" value="<?= e($editingProduct['parent_category_name'] ?? $editingProduct['category_name'] ?? '') ?>" required>
                </div>
                <div>
                  <label class="text-xs small-muted"><?= e(translate('subcategory', $lang, $translations)) ?></label>
                  <input name="prod_subcategory" class="input-dark w-full mb-2" placeholder="<?= e(translate('subcategory_ph', $lang, $translations)) ?>" value="<?= e($editingProduct['category_name'] ?? '') ?>">
                </div>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label class="text-xs small-muted"><?= e(translate('product_name', $lang, $translations)) ?></label>
                  <input name="prod_name" class="input-dark w-full mb-2" placeholder="<?= e(translate('product_name', $lang, $translations)) ?>" value="<?= e($editingProduct['name'] ?? '') ?>" required>
                </div>
                <div>
                  <label class="text-xs small-muted"><?= e(translate('brand_label', $lang, $translations)) ?></label>
                  <input name="prod_brand" class="input-dark w-full mb-2" placeholder="<?= e(translate('brand_ph', $lang, $translations)) ?>" value="<?= e($editingProduct['brand'] ?? '') ?>">
                </div>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label class="text-xs small-muted"><?= e(translate('price', $lang, $translations)) ?></label>
                  <input name="prod_price" type="number" step="1" class="input-dark w-full mb-2" value="<?= e($editingProduct['price'] ?? '0') ?>">
                </div>
                <div>
                  <label class="text-xs small-muted"><?= e(translate('sku_label', $lang, $translations)) ?></label>
                  <input name="prod_sku" class="input-dark w-full mb-2" value="<?= e($editingProduct['sku'] ?? '') ?>" placeholder="SKU-001">
                </div>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label class="text-xs small-muted"><?= e(translate('stock_status', $lang, $translations)) ?></label>
                  <select name="prod_stock_status" class="input-dark w-full mb-2">
                    <?php foreach (['in_stock','low_stock','out_of_stock','preorder'] as $stockOption): ?>
                      <option value="<?= e($stockOption) ?>" <?= (($editingProduct['stock_status'] ?? 'in_stock') === $stockOption ? 'selected' : '') ?>><?= e(translateStockStatus($stockOption, $lang, $translations)) ?></option>
                    <?php endforeach; ?>
                  </select>
                </div>
                <div class="flex items-center gap-2 pt-2">
                  <input type="checkbox" name="prod_featured" value="1" <?= (!empty($editingProduct['featured']) ? 'checked' : '') ?>>
                  <label class="text-xs small-muted"><?= e(translate('featured', $lang, $translations)) ?></label>
                </div>
              </div>
              <label class="text-xs small-muted"><?= e(translate('tags', $lang, $translations)) ?></label>
              <input name="prod_tags" class="input-dark w-full mb-2" placeholder="<?= e(translate('tags_ph', $lang, $translations)) ?>" value="<?= e($editingProduct['tags'] ?? '') ?>">
              <label class="text-xs small-muted"><?= e(translate('main_image', $lang, $translations)) ?></label>
              <input name="prod_image_file" type="file" accept="image/*" class="input-dark w-full mb-2">
              <label class="text-xs small-muted"><?= e(translate('image_url_or', $lang, $translations)) ?></label>
              <input name="prod_image" class="input-dark w-full mb-2" placeholder="https://..." value="<?= e($editingProduct['image_url'] ?? '') ?>">
              <label class="text-xs small-muted"><?= e(translate('gallery_images', $lang, $translations)) ?></label>
              <input name="prod_images[]" type="file" multiple accept="image/*" class="input-dark w-full mb-2">
              <label class="text-xs small-muted"><?= e(translate('description', $lang, $translations)) ?></label>
              <textarea name="prod_desc" class="input-dark w-full mb-2" rows="3" placeholder="<?= e(translate('description', $lang, $translations)) ?>"><?= e($editingProduct['description'] ?? '') ?></textarea>
              <div class="flex flex-wrap gap-2">
                <?php if ($editingProduct): ?>
                  <button name="seller_update_product" class="px-3 py-2 bg-amber-600 rounded text-sm"><?= e(translate('save_changes', $lang, $translations)) ?></button>
                  <a href="?lang=<?= urlencode($lang) ?>" class="px-3 py-2 border border-white/10 rounded text-sm"><?= e(translate('cancel', $lang, $translations)) ?></a>
                <?php else: ?>
                  <button name="seller_add_product" class="px-3 py-2 bg-green-600 rounded text-sm"><?= e(translate('add_button', $lang, $translations)) ?></button>
                <?php endif; ?>
              </div>
            </form>
          </div>

          <div class="card dashboard-card">
            <div class="font-medium mb-2 text-sm"><?= e(translate('store_profile_setup', $lang, $translations)) ?></div>
            <form method="post" enctype="multipart/form-data" class="space-y-2">
              <?= csrfField() ?>
                <input name="business_name" class="input-dark w-full" value="<?= e($sellerWorkspace['name'] ?? $auth['name']) ?>" placeholder="<?= e(translate('business_name_label', $lang, $translations)) ?>">
              <input name="store_name" class="input-dark w-full" value="<?= e($sellerWorkspace['store_name'] ?? $auth['name']) ?>" placeholder="<?= e(translate('shop_name_label', $lang, $translations)) ?>">
              <label class="text-xs small-muted"><?= e(translate('logo_image', $lang, $translations)) ?></label>
              <input name="store_logo_file" type="file" accept="image/*" class="input-dark w-full">
              <input name="store_logo" class="input-dark w-full" value="<?= e($sellerWorkspace['logo'] ?? '') ?>" placeholder="<?= e(translate('logo_or_url', $lang, $translations)) ?>">
              <label class="text-xs small-muted"><?= e(translate('website_label', $lang, $translations)) ?></label>
              <input name="store_website" class="input-dark w-full" value="<?= e($sellerWorkspace['website'] ?? '') ?>" placeholder="https://...">
              <textarea name="store_description" class="input-dark w-full" rows="3" placeholder="<?= e(translate('shop_description', $lang, $translations)) ?>"><?= e($sellerWorkspace['description'] ?? '') ?></textarea>
              <input name="store_address" class="input-dark w-full" value="<?= e($sellerWorkspace['address'] ?? '') ?>" placeholder="<?= e(translate('address_label', $lang, $translations)) ?>">
              <input name="store_phone" class="input-dark w-full" value="<?= e($sellerWorkspace['phone'] ?? '') ?>" placeholder="<?= e(translate('phone_label', $lang, $translations)) ?>">
              <input name="store_theme_color" class="input-dark w-full" value="<?= e($sellerWorkspace['theme_color'] ?? '#0ea5a4') ?>" placeholder="#0ea5a4">
              <input name="store_hours" class="input-dark w-full" value="<?= e($sellerWorkspace['business_hours'] ?? '') ?>" placeholder="<?= e(translate('hours_label', $lang, $translations)) ?>">
              <input name="store_social" class="input-dark w-full" value="<?= e($sellerWorkspace['social_links'] ?? '') ?>" placeholder="Instagram / Facebook / TikTok">
              <input name="store_cover" class="input-dark w-full" value="<?= e($sellerWorkspace['cover_image'] ?? '') ?>" placeholder="<?= e(translate('cover_url', $lang, $translations)) ?>">
              <input name="store_url" class="input-dark w-full" value="<?= e($sellerWorkspace['slug'] ?? '') ?>" placeholder="<?= e(translate('custom_url', $lang, $translations)) ?>">
              <button name="seller_update_profile" class="px-3 py-2 bg-cyan-600 rounded text-sm"><?= e(translate('save_profile', $lang, $translations)) ?></button>
            </form>
          </div>

          <div class="card dashboard-card xl:col-span-2">
            <div class="font-medium mb-2 text-sm"><?= e(translate('notifications_comm', $lang, $translations)) ?></div>
            <form method="post" class="space-y-2 mb-3">
              <?= csrfField() ?>
              <input name="inquiry_name" class="input-dark w-full" placeholder="<?= e(translate('inquiry_name_ph', $lang, $translations)) ?>">
              <input name="inquiry_email" class="input-dark w-full" placeholder="<?= e(translate('inquiry_email_ph', $lang, $translations)) ?>">
              <input name="inquiry_phone" class="input-dark w-full" placeholder="<?= e(translate('inquiry_phone_ph', $lang, $translations)) ?>">
              <textarea name="inquiry_message" class="input-dark w-full" rows="3" placeholder="<?= e(translate('inquiry_message_ph', $lang, $translations)) ?>"></textarea>
              <button name="customer_inquiry_submit" class="px-3 py-2 bg-cyan-600 rounded text-sm"><?= e(translate('send_inquiry', $lang, $translations)) ?></button>
            </form>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="rounded-lg border border-white/10 p-3">
                <div class="font-semibold mb-2"><?= e(translate('quick_actions', $lang, $translations)) ?></div>
                <div class="flex flex-wrap gap-2">
                  <a class="inline-flex items-center gap-1 rounded-full border border-emerald-400/30 bg-emerald-500/10 px-3 py-1.5 text-sm font-semibold text-emerald-300 hover:bg-emerald-500/20" href="<?= e(whatsappLink($defaultPhone, 'Hello, I want to follow up on my store.')) ?>" target="_blank" rel="noopener noreferrer">💬 WhatsApp</a>
                  <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="tel:<?= e($defaultPhone) ?>">📞 <?= e(translate('call', $lang, $translations)) ?></a>
                  <a class="inline-flex items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm font-semibold text-cyan-300 hover:bg-cyan-500/20" href="mailto:support@reyonic.local">✉️ <?= e(translate('email_label', $lang, $translations)) ?></a>
                </div>
              </div>
              <div class="rounded-lg border border-white/10 p-3">
                <div class="font-semibold mb-2"><?= e(translate('recent_inquiries', $lang, $translations)) ?></div>
                <?php if (empty($inquiries)): ?><div class="small-muted"><?= e(translate('no_inquiries', $lang, $translations)) ?></div><?php else: ?><div class="space-y-2"><?php foreach ($inquiries as $inquiry): ?><div class="text-sm"><div class="font-semibold"><?= e($inquiry['customer_name'] ?: translate('customer', $lang, $translations)) ?></div><div class="small-muted text-xs"><?= e($inquiry['message']) ?></div></div><?php endforeach; ?></div><?php endif; ?>
              </div>
            </div>
          </div>

          <div class="card dashboard-card xl:col-span-2">
            <div class="font-medium mb-2 text-sm"><?= e(translate('communication_history', $lang, $translations)) ?></div>
            <div class="small-muted"><?= e(translate('comm_history_hint', $lang, $translations)) ?></div>
          </div>

          <div class="card dashboard-card xl:col-span-2">
            <div class="font-medium mb-2 text-sm"><?= e(translate('your_products', $lang, $translations)) ?></div>
            <?php if (empty($prods)): ?>
              <div class="small-muted"><?= e(translate('no_products', $lang, $translations)) ?></div>
            <?php else: ?>
              <div class="space-y-2">
                <?php foreach ($prods as $p): ?>
                  <div class="flex flex-col md:flex-row md:items-start md:justify-between gap-3 border border-white/5 rounded-lg p-2">
                    <div class="flex items-start gap-3">
                      <?php if (!empty($p['image_url'])): ?>
                        <img src="<?= e($p['image_url']) ?>" alt="<?= e($p['name']) ?>" class="w-12 h-12 rounded-lg object-cover border border-white/10">
                      <?php endif; ?>
                      <div>
                        <div class="font-semibold text-sm"><?= e($p['name']) ?></div>
                        <div class="small-muted text-xs"><?= e($p['category_name']) ?> • <?= e(number_format((float) $p['price'], 0)) ?> IQD</div>
                        <div class="small-muted text-xs mt-1"><?= e(translate('sku_label', $lang, $translations)) ?>: <?= e($p['sku'] ?? '-') ?> • <?= e(translateStockStatus((string) ($p['stock_status'] ?? 'in_stock'), $lang, $translations)) ?></div>
                        <?php if (!empty($p['featured'])): ?>
                          <span class="inline-block mt-1 rounded-full bg-amber-500/20 px-2 py-0.5 text-[10px] uppercase tracking-[0.2em] text-amber-300"><?= e(translate('featured_badge', $lang, $translations)) ?></span>
                        <?php endif; ?>
                      </div>
                    </div>
                    <div class="flex flex-col items-start md:items-end gap-2">
                      <div class="small-muted text-xs"><?= e(date('Y-m-d', strtotime($p['created_at'] ?? 'now'))) ?></div>
                      <div class="flex gap-2">
                        <a href="?lang=<?= urlencode($lang) ?>&edit_product=<?= e($p['id']) ?>" class="text-xs text-cyan-300"><?= e(translate('edit', $lang, $translations)) ?></a>
                        <form method="post" class="inline">
                          <?= csrfField() ?>
                          <input type="hidden" name="product_id" value="<?= e($p['id']) ?>">
                          <button name="seller_delete_product" class="text-xs text-rose-300"><?= e(translate('delete', $lang, $translations)) ?></button>
                        </form>
                      </div>
                    </div>
                  </div>
                <?php endforeach; ?>
              </div>
            <?php endif; ?>
          </div>
        </div>
      </section>
    <?php endif; ?>
    <?php endif; ?>

    <!-- Footer -->
    <footer class="mt-8 text-center small-muted">
      <?= e(translate('footer', $lang, $translations)) ?>
    </footer>
  </div>

  <div id="imageZoomModal" class="image-zoom-modal" role="dialog" aria-label="Image zoom">
    <div class="max-w-5xl w-full flex justify-end mb-3">
      <button id="closeImageZoom" class="btn-ghost"><?= e(translate('close', $lang, $translations)) ?></button>
    </div>
    <img id="zoomedImage" src="" alt="Zoomed product image">
  </div>

  <!-- Login Modal (Customer & Seller) -->
  <div id="loginModal" class="modal-backdrop" style="display:none;">
    <div class="modal">
      <div class="flex items-center justify-between mb-3">
        <div class="font-semibold"><?= e(translate('login_title', $lang, $translations)) ?></div>
        <button id="closeModal" class="btn-ghost"><?= e(translate('close', $lang, $translations)) ?></button>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <!-- Customer quick login -->
        <div id="customerLoginPanel" class="card">
          <div class="font-medium mb-2"><?= e(translate('customer_quick', $lang, $translations)) ?></div>
          <form method="post">
            <?= csrfField() ?>
            <label class="text-xs small-muted"><?= e(translate('customer_name', $lang, $translations)) ?></label>
            <input name="cust_name" class="input-dark w-full mb-2" placeholder="<?= e(translate('customer_name', $lang, $translations)) ?>">
            <label class="text-xs small-muted"><?= e(translate('customer_email', $lang, $translations)) ?></label>
            <input name="cust_email" type="email" class="input-dark w-full mb-2" placeholder="you@example.com" required>
            <button name="customer_login" class="px-3 py-2 bg-indigo-600 rounded text-sm w-full"><?= e(translate('customer_button', $lang, $translations)) ?></button>
          </form>
        </div>

        <!-- Seller login -->
        <div id="sellerLoginPanel" class="card">
          <div class="font-medium mb-2"><?= e(translate('seller', $lang, $translations)) ?></div>
          <?php if (!empty($login_error)): ?><div class="small-muted mb-2 text-red-400"><?= e(translate('invalid_seller', $lang, $translations)) ?></div><?php endif; ?>
          <form method="post">
            <?= csrfField() ?>
            <label class="text-xs small-muted"><?= e(translate('customer_email', $lang, $translations)) ?></label>
            <input name="seller_email" type="email" class="input-dark w-full mb-2" placeholder="seller@example.com" required>
            <label class="text-xs small-muted"><?= e(translate('seller_password', $lang, $translations)) ?></label>
            <input name="seller_password" type="password" class="input-dark w-full mb-2" placeholder="password (prototype)">
            <button name="seller_login" class="px-3 py-2 bg-amber-600 rounded text-sm w-full"><?= e(translate('seller_button', $lang, $translations)) ?></button>
            <div class="small-muted text-xs mt-2"><?= e(translate('seller_helper', $lang, $translations)) ?></div>
          </form>
        </div>

        <!-- Admin login -->
        <div id="adminLoginPanel" class="card hidden">
          <div class="font-medium mb-2"><?= e(translate('admin', $lang, $translations)) ?></div>
          <?php if (!empty($login_error)): ?><div class="small-muted mb-2 text-red-400"><?= e(translate('invalid_seller', $lang, $translations)) ?></div><?php endif; ?>
          <form method="post">
            <?= csrfField() ?>
            <input type="hidden" name="seller_email" value="<?= e(ADMIN_EMAIL) ?>">
            <label class="text-xs small-muted"><?= e(translate('customer_email', $lang, $translations)) ?></label>
            <input type="email" class="input-dark w-full mb-2" value="<?= e(ADMIN_EMAIL) ?>" disabled>
            <label class="text-xs small-muted"><?= e(translate('seller_password', $lang, $translations)) ?></label>
            <input name="seller_password" type="password" class="input-dark w-full mb-2" placeholder="password" required>
            <label class="text-xs small-muted">Admin setup key (first time only)</label>
            <input name="admin_setup_key" type="text" class="input-dark w-full mb-2" placeholder="Enter setup key if admin user is not created yet">
            <button name="seller_login" class="px-3 py-2 bg-cyan-600 rounded text-sm w-full">Admin Login</button>
            <div class="small-muted text-xs mt-2">If admin user is not created yet, enter the admin setup key here.</div>
          </form>
        </div>
      </div>
    </div>
  </div>

<?php if ($auth && $auth['type'] === 'seller'): ?>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
  (function(){
    try {
      const dailyRows = <?= json_encode(array_values($salesSummary['daily_series'] ?? []), JSON_HEX_TAG) ?>;
      const monthlyRows = <?= json_encode(array_values($salesSummary['monthly_series'] ?? []), JSON_HEX_TAG) ?>;

      const dailyLabels = dailyRows.map(r => r.d);
      const dailyData = dailyRows.map(r => parseFloat(r.revenue || 0));

      const monthlyLabels = monthlyRows.map(r => r.month_start);
      const monthlyData = monthlyRows.map(r => parseFloat(r.revenue || 0));

      const dailyCtx = document.getElementById('salesDailyChart');
      if (dailyCtx && dailyLabels.length) {
        new Chart(dailyCtx, {
          type: 'line',
          data: {
            labels: dailyLabels,
            datasets: [{ label: <?= json_encode(translate('chart_revenue', $lang, $translations), JSON_HEX_TAG) ?>, data: dailyData, borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.15)', fill: true, tension: 0.2 }]
          },
          options: { responsive: true, scales: { x: { ticks: { maxRotation: 45, autoSkip: true } }, y: { beginAtZero: true } } }
        });
      }

      const monthlyCtx = document.getElementById('salesMonthlyChart');
      if (monthlyCtx && monthlyLabels.length) {
        new Chart(monthlyCtx, {
          type: 'bar',
          data: {
            labels: monthlyLabels,
            datasets: [{ label: <?= json_encode(translate('chart_revenue', $lang, $translations), JSON_HEX_TAG) ?>, data: monthlyData, backgroundColor: '#0ea5a4' }]
          },
          options: { responsive: true, scales: { x: { ticks: { maxRotation: 45 } }, y: { beginAtZero: true } } }
        });
      }
    } catch (e) {
      console.error('Chart init error', e);
    }
  })();
</script>
<?php endif; ?>
<script>
  const modal = document.getElementById('loginModal');
  const imageModal = document.getElementById('imageZoomModal');
  const zoomedImage = document.getElementById('zoomedImage');
  const closeImageZoom = document.getElementById('closeImageZoom');
  const mainProductImage = document.getElementById('productMainImage');
  const loginButton = document.getElementById('openLogin');
  const adminLoginButton = document.getElementById('openAdminLogin');
  const closeModalButton = document.getElementById('closeModal');
  const customerLoginPanel = document.getElementById('customerLoginPanel');
  const sellerLoginPanel = document.getElementById('sellerLoginPanel');
  const adminLoginPanel = document.getElementById('adminLoginPanel');

  const showLoginPanel = (panel) => {
    if (!customerLoginPanel || !sellerLoginPanel || !adminLoginPanel) return;
    customerLoginPanel.classList.toggle('hidden', panel !== 'default');
    sellerLoginPanel.classList.toggle('hidden', panel !== 'default');
    adminLoginPanel.classList.toggle('hidden', panel !== 'admin');
  };

  if (loginButton && modal) {
    loginButton.addEventListener('click', () => {
      showLoginPanel('default');
      modal.style.display = 'flex';
    });
  }
  if (adminLoginButton && modal) {
    adminLoginButton.addEventListener('click', () => {
      showLoginPanel('admin');
      modal.style.display = 'flex';
    });
  }
  if (closeModalButton && modal) {
    closeModalButton.addEventListener('click', () => modal.style.display = 'none');
  }
  if (closeImageZoom && imageModal) {
    closeImageZoom.addEventListener('click', () => { imageModal.style.display = 'none'; });
  }
  if (imageModal) {
    imageModal.addEventListener('click', (e) => { if (e.target === imageModal) imageModal.style.display = 'none'; });
  }
  if (mainProductImage && zoomedImage && imageModal) {
    mainProductImage.addEventListener('click', () => { zoomedImage.src = mainProductImage.src; imageModal.style.display = 'flex'; });
  }

  document.querySelectorAll('.gallery-thumb').forEach((thumb) => {
    thumb.addEventListener('click', () => {
      const image = thumb.getAttribute('data-image');
      const main = document.getElementById('productMainImage');
      if (!main || !image) return;
      main.src = image;
      document.querySelectorAll('.gallery-thumb').forEach((item) => item.classList.remove('active'));
      thumb.classList.add('active');
      if (zoomedImage) zoomedImage.src = image;
      if (mainProductImage && zoomedImage && imageModal) {
        mainProductImage.addEventListener('click', () => { zoomedImage.src = image; imageModal.style.display = 'flex'; });
      }
    });
  });

  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        const q = encodeURIComponent(this.value.trim());
        const lang = new URLSearchParams(window.location.search).get('lang') || 'en';
        window.location.href = '?q=' + q + '&lang=' + lang;
      }
    });
  }

  const myShopToggle = document.getElementById('myShopToggle');
  if (myShopToggle) {
    myShopToggle.addEventListener('click', function() {
      const sellerSection = document.querySelector('section.mt-6');
      if (sellerSection) {
        sellerSection.scrollIntoView({ behavior: 'smooth' });
      }
    });
  }

  const previewBox = document.getElementById('shopPreviewBox');
  const primaryInput = document.getElementById('storePrimaryColor');
  const secondaryInput = document.getElementById('storeSecondaryColor');
  const swatches = document.querySelectorAll('.theme-swatch');
  const publicLinkInput = document.getElementById('publicProfileLink');
  const copyProfileLink = document.getElementById('copyProfileLink');
  const downloadQrButton = document.getElementById('downloadQrButton');
  const shopProfileQr = document.getElementById('shopProfileQr');

  function updatePreviewTheme(primary, secondary) {
    if (!previewBox) return;
    previewBox.style.setProperty('--preview-primary', primary);
    previewBox.style.setProperty('--preview-secondary', secondary);
  }

  if (primaryInput && secondaryInput) {
    primaryInput.addEventListener('input', () => updatePreviewTheme(primaryInput.value, secondaryInput.value));
    secondaryInput.addEventListener('input', () => updatePreviewTheme(primaryInput.value, secondaryInput.value));
  }

  swatches.forEach((swatch) => {
    swatch.addEventListener('click', () => {
      const primary = swatch.dataset.primary;
      const secondary = swatch.dataset.secondary;
      if (!primary || !secondary) return;
      swatches.forEach((item) => item.classList.remove('selected'));
      swatch.classList.add('selected');
      if (primaryInput) primaryInput.value = primary;
      if (secondaryInput) secondaryInput.value = secondary;
      updatePreviewTheme(primary, secondary);
    });
  });

  if (copyProfileLink) {
    copyProfileLink.addEventListener('click', () => {
      if (!publicLinkInput) return;
      const copyLabel = copyProfileLink.dataset.copyLabel || 'Copy';
      const copiedLabel = copyProfileLink.dataset.copiedLabel || 'Copied';
      navigator.clipboard?.writeText(publicLinkInput.value).then(() => {
        copyProfileLink.textContent = copiedLabel;
        setTimeout(() => { copyProfileLink.textContent = copyLabel; }, 1500);
      }).catch(() => {
        publicLinkInput.select();
        document.execCommand('copy');
      });
    });
  }

  if (downloadQrButton && shopProfileQr) {
    downloadQrButton.addEventListener('click', () => {
      const link = document.createElement('a');
      link.href = shopProfileQr.src;
      link.download = 'shop-profile-qr.png';
      document.body.appendChild(link);
      link.click();
      link.remove();
    });
  }
</script>
</body>