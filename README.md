# PHP Media Gallery

A lightweight, self-hosted PHP gallery for browsing and downloading photographs and videos directly from a web server directory.
Developed and security reviewed with the help of an llm.

## Features

### Media Gallery
- Browse photographs and videos in a clean, browser-based gallery.
- Automatically discovers supported media files in the gallery root and its subdirectories.
- Preserves the directory structure when browsing collections.
- No database or external media service required.

### Photo Support
- HEIC/HEIF photograph support through ImageMagick.
- Automatic generation of browser-compatible image previews.
- Cached image conversions to avoid unnecessary repeated processing.
- Original photographs remain available for download.
- Validates HEIC/HEIF file signatures, sizes, dimensions and frame count before conversion.

### Video Support
- MOV video discovery and previews.
- Browser-based playback where supported by the browser and video codecs.
- Direct download buttons for individual video files.
- Original video files are not modified.

### Downloads
- Download individual original photographs and videos.
- **Download all:** Package the gallery's media files into a ZIP archive.
- ZIP generation is subject to configurable file-count and size limits.

### Performance and Resource Management
- Generated image previews are cached locally.
- File locks prevent duplicate simultaneous conversions.
- Limits simultaneous image conversions and ZIP generation.
- Bounds recursive scanning depth and the number of scanned files.
- Applies limits to generated image sizes and ZIP archive sizes.

### Privacy and Deployment
- Self-hosted: media stays on your own hosting account.
- No database, external asset CDN or third-party media service required.
- No external image-processing API.
- Suitable for a simple public media collection on conventional PHP hosting.

## Requirements

- PHP 8.0 or newer.
- PHP Imagick extension with HEIC/HEIF support.
- PHP ZipArchive extension for the optional **Download all** feature.
- Web-server account with read access to media files and write access to the application cache directory.

## Installation

1. Upload `index.php` to the directory you want to use as the gallery.
2. Place your photographs and videos in that directory or its subdirectories.
3. Ensure the PHP process has permission to read the media files.
4. Ensure the PHP process can create and write to the `_files` directory.
5. Open the directory URL in your browser.

## Public Access

Anyone who discovers this gallery's URL can browse and download its media.

**Do not put confidential files in this directory.** Keep it dedicated to media that is intentionally public.

## Application-Level Security

- Only regular, non-symlink media files beneath this directory are served.
- HEIC/HEIF signatures, file sizes, and decoded dimensions are checked.
- ImageMagick resource limits are applied before decoding.
- HEIC/HEIF data is validated and decoded from a private local temporary file. No user-controlled ImageMagick options or delegates are supplied.
- Generated cache files are stored under `_files/`, with an Apache deny rule where supported. This does not protect the cache on every web server.
- Recursive scanning, ZIP generation and image conversion are subject to application-level workload limits.

## Hosting and Infrastructure Security

**The following protections cannot be fully enforced by this PHP application. They require hosting-provider or server-level configuration.**

- **ImageMagick and libheif:** These are native parsers. Keep them patched and, where possible, run decoding in a restricted OS or container sandbox. PHP-level checks and Imagick resource limits are not a security sandbox.
- **ImageMagick policy:** Ask the hosting provider to enforce a restrictive ImageMagick policy. Disable network/remote protocols, unnecessary coders and delegates, and indirect reads. A user-level `policy.xml` is useful only if the host actually loads and enforces it. This application cannot reliably verify that.
- **Request and concurrency limits:** PHP cannot impose reliable global request or concurrency limits. Configure web-server/PHP-FPM limits, CPU and memory quotas, request timeouts, and rate limiting to reduce denial-of-service and conversion-exhaustion risks.
- **Resource consumption:** Recursive media scanning and ZIP generation consume resources. Keep the collection reasonably sized and apply host-level execution and storage limits.
- **Application workload limits:** This script bounds recursive scan entries and depth, collection size, ZIP file count and total bytes, and simultaneous image/ZIP generation. These application-level limits do not replace host-level quotas or rate limiting.
- **Cache directory protection:** The `_files` directory must be inaccessible over HTTP. The generated `.htaccess` rule works only on Apache when overrides are enabled. Nginx and other servers require equivalent server-level deny rules. Prefer storing cache and temporary data outside the document root when the host permits it.
- **Gallery directory protection:** Protect the gallery directory at the web-server level. PHP path checks do not prevent direct HTTP access to unrelated files, backups, dotfiles, or files exposed by server aliases or symlinks.
- **HTTPS and HSTS:** Use HTTPS and configure HSTS at the web-server or proxy level. PHP response headers do not cover static files served directly by the web server.
- **Filesystem security:** Correct filesystem ownership and permissions, and reliable backups, remain hosting responsibilities. PHP path checks cannot eliminate every filesystem race condition.

## Warnings and Diagnostics

Set `SHOW_SECURITY_WARNING` to `false` to suppress the visible gallery notice.

Startup diagnostics and warnings continue to be written to the PHP error log.

**This application cannot confirm provider-level security settings.**


The software is provided "as is", without warranty of any kind.
