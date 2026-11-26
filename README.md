Here is the text formatted as Markdown, ready to save as README.md:

PHP Media Gallery

Purpose and Requirements

A public gallery for locally stored HEIC/HEIF photographs and MOV videos.

Requirements:

* PHP 8.0 or newer.
* PHP Imagick extension with HEIC/HEIF support.
* PHP ZipArchive extension for the optional Download all feature.

Public Access

Anyone who discovers this gallery’s URL can browse and download its media.

Do not put confidential files in this directory. Keep this directory dedicated to media that is intentionally public.

Application-Level Security

* Only regular, non-symlink media files beneath this directory are served.
* HEIC/HEIF signatures, file sizes, and decoded dimensions are checked.
* ImageMagick resource limits are applied before decoding.
* HEIC/HEIF data is validated and decoded from a private local temporary file. No user-controlled ImageMagick options or delegates are supplied.
* Generated cache files are stored under _files/, with an Apache deny rule where supported. This does not protect the cache on every web server.

Hosting and Infrastructure Security

The following protections cannot be fully enforced by this PHP application. They require hosting-provider or server-level configuration.

* ImageMagick and libheif: These are native parsers. Keep them patched and, where possible, run decoding in a restricted OS or container sandbox. PHP-level checks and Imagick resource limits are not a security sandbox.
* ImageMagick policy: Ask the hosting provider to enforce a restrictive ImageMagick policy. Disable network/remote protocols, unnecessary coders and delegates, and indirect reads. A user-level policy.xml is useful only if the host actually loads and enforces it. This application cannot reliably verify that.
* Request and concurrency limits: PHP cannot impose reliable global request or concurrency limits. Configure web-server/PHP-FPM limits, CPU and memory quotas, request timeouts, and rate limiting to reduce denial-of-service and conversion-exhaustion risks.
* Resource consumption: Recursive media scanning and ZIP generation consume resources. Keep the collection reasonably sized and apply host-level execution and storage limits.
* Application workload limits: This script bounds recursive scan entries and depth, collection size, ZIP file count and total bytes, and simultaneous image/ZIP generation. These application-level limits do not replace host-level quotas or rate limiting.
* Cache directory protection: The _files directory must be inaccessible over HTTP. The generated .htaccess rule works only on Apache when overrides are enabled. Nginx and other servers require equivalent server-level deny rules. Prefer storing cache and temporary data outside the document root when the host permits it.
* Gallery directory protection: Protect the gallery directory at the web-server level. PHP path checks do not prevent direct HTTP access to unrelated files, backups, dotfiles, or files exposed by server aliases or symlinks.
* HTTPS and HSTS: Use HTTPS and configure HSTS at the web-server or proxy level. PHP response headers do not cover static files served directly by the web server.
* Filesystem security: Correct filesystem ownership and permissions, and reliable backups, remain hosting responsibilities. PHP path checks cannot eliminate every filesystem race condition.

Warnings and Diagnostics

Set SHOW_SECURITY_WARNING to false to suppress the visible gallery notice.

Startup diagnostics and warnings continue to be written to the PHP error log.

This application cannot confirm provider-level security settings.
