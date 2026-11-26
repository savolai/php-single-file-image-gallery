<?php
/*
 * PHP MEDIA GALLERY 
 * PURPOSE AND REQUIREMENTS
 * Public gallery for local HEIC/HEIF photographs and MOV videos.
 * Requires PHP 8.0+, Imagick with HEIC/HEIF support, and ZipArchive for
 * the optional "Download all" feature.

MIT License

Copyright (c) 2026 Olli Savolainen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

 
 * PUBLIC ACCESS
 * Anyone who discovers this gallery URL can browse and download its media.
 * Do not put confidential files in this directory. Keep this directory
 * dedicated to media that is intentionally public.
 *
 * APPLICATION-LEVEL SECURITY
 * - Only regular, non-symlink media files beneath this directory are served.
 * - HEIC/HEIF signatures, file sizes and decoded dimensions are checked.
 * - ImageMagick resource limits are applied before decoding.
 * - HEIC/HEIF data is validated and decoded from a private local temporary
 *   file; no user-controlled ImageMagick options or delegates are supplied.
 * - Generated cache files are stored under _files/ with an Apache deny rule
 *   where supported. This does not protect the cache on every web server.
 *
 * HOSTING / INFRASTRUCTURE SECURITY — NOT ENFORCEABLE BY THIS PHP FILE
 * - ImageMagick and libheif are native parsers. Keep them patched and, where
 *   possible, run decoding in a restricted OS/container sandbox. PHP-level
 *   checks and Imagick resource limits are not a security sandbox.
 * - Ask the hosting provider to enforce a restrictive ImageMagick policy:
 *   disable network/remote protocols, unnecessary coders and delegates, and
 *   indirect reads. A user policy.xml is useful only if the host actually
 *   loads and enforces it; this application cannot verify that reliably.
 * - PHP cannot impose reliable global request/concurrency limits. Configure
 *   web-server/PHP-FPM limits, CPU and memory quotas, request timeouts, and
 *   rate limiting to reduce denial-of-service and conversion-exhaustion risk.
 * - Recursive media scanning and ZIP generation consume resources. Keep the
 *   collection reasonably sized and apply host-level execution/storage limits.
 * - This script bounds recursive scan entries/depth, collection size, ZIP
 *   file count/total bytes, and simultaneous image/ZIP generation. These
 *   application limits do not replace host-level quotas or rate limiting.
 * - The _files directory must be inaccessible over HTTP. The generated
 *   .htaccess rule works only on Apache when overrides are enabled; Nginx and
 *   other servers require equivalent server-level deny rules. Prefer storing
 *   cache/temp data outside the document root when the host permits it.
 * - Protect the gallery directory at the web-server level. PHP path checks
 *   do not prevent direct HTTP access to unrelated files, backups, dotfiles,
 *   or files exposed by server aliases/symlinks.
 * - Use HTTPS and configure HSTS at the web-server/proxy level. PHP response
 *   headers do not cover static files served directly by the web server.
 * - Correct filesystem ownership/permissions and reliable backups remain
 *   hosting responsibilities. PHP path checks cannot eliminate every
 *   filesystem race condition.
 *
 * WARNINGS AND DIAGNOSTICS
 * Set SHOW_SECURITY_WARNING to false to suppress the visible gallery notice.
 * Startup diagnostics and warnings continue to be written to the PHP error
 * log. This application cannot confirm provider-level security settings.
 *
 * This software is provided without warranty. Public-domain dedication does
 * not remove obligations relating to third-party libraries, media, or data.
 */

declare(strict_types=1);

// --------------------------------------------------------------------------
// CONFIGURATION
// --------------------------------------------------------------------------

const SHOW_SECURITY_WARNING = false;

const MAX_IMAGE_FILE_SIZE = 50 * 1024 * 1024;
const MAX_GENERATED_IMAGE_BYTES = 256 * 1024 * 1024;
const MAX_IMAGE_PIXELS = 40000000;
const MAX_IMAGE_DIMENSION = 10000;
const THUMBNAIL_SIZE = 800;
const IMAGE_TIMEOUT = 20;

const IMAGE_MEMORY_LIMIT = 128; // MiB
const IMAGE_MAP_LIMIT = 256;    // MiB
const IMAGE_DISK_LIMIT = 512;   // MiB
const IMAGE_THREAD_LIMIT = 2;

// Application-level workload bounds. Adjust to the hosting account's limits.
const MAX_SCAN_ENTRIES = 20000;
const MAX_SCAN_MEDIA_FILES = 5000;
const MAX_SCAN_DEPTH = 12;
const MAX_ZIP_FILES = 2000;
const MAX_ZIP_TOTAL_BYTES = 1073741824; // 1 GiB
const MAX_CONCURRENT_CONVERSIONS = 2;

const IMAGE_EXTENSIONS = ['heic', 'heif'];
const VIDEO_EXTENSIONS = ['mov'];

// --------------------------------------------------------------------------
// ROOT AND STORAGE
// --------------------------------------------------------------------------

$root = realpath(__DIR__);
if ($root === false || !is_dir($root)) {
    http_response_code(500);
    exit('Gallery directory unavailable.');
}

$storage = $root . '/_files';
$cacheImages = $storage . '/cache/images';
$cacheConverted = $storage . '/cache/converted';
$cacheZip = $storage . '/zip';

// --------------------------------------------------------------------------
// GENERAL HELPERS
// --------------------------------------------------------------------------

function logGallery(string $message): void
{
    error_log('[Media Gallery] ' . $message);
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function insideRoot(string $path): bool
{
    global $root;

    $real = realpath($path);
    if ($real === false) {
        return false;
    }

    $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    return str_starts_with($real, $prefix);
}

function isRegularFile(string $path): bool
{
    $stat = @lstat($path);
    return $stat !== false && (($stat['mode'] & 0170000) === 0100000);
}

/**
 * Resolve a gallery-relative path. Reject traversal and symlinks in every
 * component, and return a canonical path for a regular file beneath root.
 */
function safeMediaPath(string $relative): string|false
{
    global $root;

    if (
        $relative === '' ||
        strlen($relative) > 4096 ||
        str_contains($relative, "\0") ||
        preg_match('/[\x00-\x1F\x7F]/', $relative)
    ) {
        return false;
    }

    if (
        str_starts_with($relative, '/') ||
        str_starts_with($relative, '\\') ||
        preg_match('/^[a-zA-Z]:/', $relative)
    ) {
        return false;
    }

    $parts = explode('/', $relative);
    foreach ($parts as $part) {
        if ($part === '' || $part === '.' || $part === '..' || str_contains($part, '\\')) {
            return false;
        }
    }

    $current = $root;
    foreach ($parts as $part) {
        $current .= DIRECTORY_SEPARATOR . $part;
        if (is_link($current)) {
            return false;
        }
    }

    if (!isRegularFile($current) || !insideRoot($current)) {
        return false;
    }

    return realpath($current) ?: false;
}

/**
 * Read from one already-open file handle. fstat() checks the object actually
 * opened, reducing path-based TOCTOU exposure between validation and reading.
 */
function readValidatedFile(string $path, int $maximumBytes): string
{
    if (!isRegularFile($path) || !insideRoot($path)) {
        throw new RuntimeException('Invalid local input file.');
    }

    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Could not open input file.');
    }

    try {
        $before = fstat($handle);
        if (
            $before === false ||
            (($before['mode'] & 0170000) !== 0100000) ||
            $before['size'] < 1 ||
            $before['size'] > $maximumBytes
        ) {
            throw new RuntimeException('Input file size or type is outside permitted limits.');
        }

        $data = stream_get_contents($handle, $maximumBytes + 1);
        if ($data === false || $data === '' || strlen($data) > $maximumBytes) {
            throw new RuntimeException('Could not read a valid input file.');
        }

        $after = fstat($handle);
        if (
            $after === false ||
            $before['dev'] !== $after['dev'] ||
            $before['ino'] !== $after['ino'] ||
            $before['size'] !== $after['size'] ||
            $before['mtime'] !== $after['mtime'] ||
            strlen($data) !== $after['size']
        ) {
            throw new RuntimeException('Input file changed while being read.');
        }

        return $data;
    } finally {
        fclose($handle);
    }
}

/** Acquire one of a small number of cross-request conversion slots. */
function acquireConversionSlot(): mixed
{
    global $storage;

    for ($i = 0; $i < MAX_CONCURRENT_CONVERSIONS; $i++) {
        $path = $storage . '/conversion-slot-' . $i . '.lock';
        $handle = @fopen($path, 'c');
        if ($handle !== false && @flock($handle, LOCK_EX | LOCK_NB)) {
            return $handle;
        }
        if (is_resource($handle)) {
            fclose($handle);
        }
    }

    return false;
}

// --------------------------------------------------------------------------
// STORAGE INITIALIZATION
// --------------------------------------------------------------------------

function initializeStorage(): void
{
    global $root, $storage, $cacheImages, $cacheConverted, $cacheZip;

    $directories = [
        $storage,
        $storage . '/cache',
        $cacheImages,
        $cacheConverted,
        $cacheZip,
    ];

    foreach ($directories as $directory) {
        if (is_link($directory)) {
            throw new RuntimeException('Storage path must not be a symbolic link.');
        }

        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Cannot initialize gallery storage.');
        }

        $real = realpath($directory);
        $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if ($real === false || !str_starts_with($real, $prefix)) {
            throw new RuntimeException('Storage path resolves outside gallery root.');
        }

        if (!is_writable($directory)) {
            throw new RuntimeException('Gallery storage is not writable.');
        }
    }

    $htaccess = $storage . '/.htaccess';
    if (is_link($htaccess) || (file_exists($htaccess) && !is_file($htaccess))) {
        throw new RuntimeException('Storage .htaccess must be a regular, non-symlink file.');
    }
    $denyRules = "Options -Indexes\nRequire all denied\n";
    if (@file_get_contents($htaccess) !== $denyRules) {
        if (@file_put_contents($htaccess, $denyRules, LOCK_EX) === false) {
            logGallery('Could not enforce storage .htaccess; verify web-server protection manually.');
        }
    }

    $index = $storage . '/index.html';
    if (is_link($index)) {
        throw new RuntimeException('Storage index file must not be a symbolic link.');
    }
    if (!file_exists($index)) {
        @file_put_contents($index, '');
    }

    foreach ($directories as $directory) {
        @chmod($directory, 0700);
    }
}

try {
    initializeStorage();
} catch (Throwable $e) {
    logGallery('Storage initialization failed: ' . $e->getMessage());
    http_response_code(500);
    exit('Gallery storage initialization failed.');
}

// --------------------------------------------------------------------------
// HTTP SECURITY HEADERS
// --------------------------------------------------------------------------

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; media-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'");

// --------------------------------------------------------------------------
// IMAGEMAGICK RESOURCE LIMITS
// --------------------------------------------------------------------------

function configureImagick(): void
{
    if (!extension_loaded('imagick')) {
        throw new RuntimeException('Imagick PHP extension is unavailable.');
    }

    $limits = [
        Imagick::RESOURCETYPE_MEMORY => IMAGE_MEMORY_LIMIT,
        Imagick::RESOURCETYPE_MAP => IMAGE_MAP_LIMIT,
        Imagick::RESOURCETYPE_DISK => IMAGE_DISK_LIMIT,
        Imagick::RESOURCETYPE_THREAD => IMAGE_THREAD_LIMIT,
        Imagick::RESOURCETYPE_TIME => IMAGE_TIMEOUT,
        Imagick::RESOURCETYPE_AREA => MAX_IMAGE_PIXELS,
    ];

    foreach ($limits as $type => $value) {
        if (!Imagick::setResourceLimit($type, $value)) {
            throw new RuntimeException('Could not set an Imagick resource limit.');
        }
    }

    if (function_exists('set_time_limit')) {
        @set_time_limit(IMAGE_TIMEOUT + 5);
    }
}

// --------------------------------------------------------------------------
// HEIC/HEIF SIGNATURE AND DECODING
// --------------------------------------------------------------------------

/**
 * Validate an ISO-BMFF ftyp box and a recognized HEIF brand.
 * This is a preliminary check, not a substitute for decoding.
 */
function validHeifSignature(string $data): bool
{
    if (strlen($data) < 16 || substr($data, 4, 4) !== 'ftyp') {
        return false;
    }

    $boxSize = unpack('N', substr($data, 0, 4))[1] ?? 0;
    if ($boxSize < 16 || $boxSize > strlen($data)) {
        return false;
    }

    $brands = [
        'heic', 'heix', 'hevc', 'hevx',
        'mif1', 'msf1', 'heim', 'heis',
        'hevm', 'hevs',
    ];

    if (in_array(substr($data, 8, 4), $brands, true)) {
        return true;
    }

    for ($offset = 16; $offset + 4 <= min($boxSize, strlen($data)); $offset += 4) {
        if (in_array(substr($data, $offset, 4), $brands, true)) {
            return true;
        }
    }

    return false;
}

/**
 * Decode a validated HEIC/HEIF file.
 *
 * Important host-specific workaround:
 * This Kapsi ImageMagick build can decode HEIC from a filesystem path
 * (Imagick::readImage), but the gallery's previous readImageBlob path failed
 * with "Unable to read image blob". We therefore validate the bytes, write
 * those exact bytes to a random private temporary file in our protected
 * cache, and decode that local file. No user-controlled filename or
 * ImageMagick option is passed to ImageMagick.
 */
function loadHeif(string $sourcePath): Imagick
{
    global $cacheImages;

    if (!insideRoot($sourcePath) || !isRegularFile($sourcePath)) {
        throw new RuntimeException('Invalid local source path.');
    }

    $data = readValidatedFile($sourcePath, MAX_IMAGE_FILE_SIZE);
    if (!validHeifSignature($data)) {
        throw new RuntimeException('Invalid HEIC/HEIF file signature.');
    }

    configureImagick();

    $tempPath = $cacheImages . '/' . bin2hex(random_bytes(16)) . '.heic-tmp';
    $handle = @fopen($tempPath, 'x+b');
    if ($handle === false) {
        throw new RuntimeException('Could not create private image input file.');
    }

    try {
        @chmod($tempPath, 0600);

        $length = strlen($data);
        $written = 0;
        while ($written < $length) {
            $count = fwrite($handle, substr($data, $written, 1024 * 1024));
            if ($count === false || $count === 0) {
                throw new RuntimeException('Could not write private image input file.');
            }
            $written += $count;
        }

        if (!fflush($handle)) {
            throw new RuntimeException('Could not flush private image input file.');
        }
        fclose($handle);
        $handle = null;

        $probe = new Imagick();
        try {
            if (!$probe->pingImage($tempPath)) {
                throw new RuntimeException('Could not inspect HEIC/HEIF image.');
            }

            if ($probe->getNumberImages() !== 1) {
                throw new RuntimeException('Only single-image HEIC/HEIF files are accepted.');
            }

            $width = $probe->getImageWidth();
            $height = $probe->getImageHeight();

            if (
                $width < 1 ||
                $height < 1 ||
                $width > MAX_IMAGE_DIMENSION ||
                $height > MAX_IMAGE_DIMENSION ||
                ($width * $height) > MAX_IMAGE_PIXELS
            ) {
                throw new RuntimeException('Image dimensions exceed permitted limits.');
            }
        } finally {
            $probe->clear();
            $probe->destroy();
        }

        $image = new Imagick();
        try {
            if (!$image->readImage($tempPath)) {
                throw new RuntimeException('HEIC/HEIF decoding failed.');
            }

            if ($image->getNumberImages() !== 1) {
                throw new RuntimeException('Decoded HEIC/HEIF must contain exactly one image.');
            }

            $image->setIteratorIndex(0);
            $image->setFirstIterator();

            $format = strtoupper($image->getImageFormat());
            if (!in_array($format, ['HEIC', 'HEIF'], true)) {
                throw new RuntimeException('Unexpected decoded image format.');
            }

            $width = $image->getImageWidth();
            $height = $image->getImageHeight();
            if (
                $width < 1 ||
                $height < 1 ||
                $width > MAX_IMAGE_DIMENSION ||
                $height > MAX_IMAGE_DIMENSION ||
                ($width * $height) > MAX_IMAGE_PIXELS
            ) {
                throw new RuntimeException('Decoded image dimensions exceed limits.');
            }

            if (method_exists($image, 'autoOrientImage')) {
                $image->autoOrientImage();
            }

            return $image;
        } catch (Throwable $e) {
            $image->clear();
            $image->destroy();
            throw $e;
        }
    } finally {
        if (is_resource($handle)) {
            fclose($handle);
        }
        if (is_file($tempPath) || is_link($tempPath)) {
            @unlink($tempPath);
        }
        unset($data);
    }
}

// --------------------------------------------------------------------------
// OPTIONAL USER-LEVEL POLICY DIAGNOSTIC
// --------------------------------------------------------------------------

function inspectImageMagickPolicy(): array
{
    $result = [
        'candidate_found' => false,
        'candidate_readable' => false,
        'paths' => [],
    ];

    $candidates = [];
    $home = getenv('HOME');

    if (is_string($home) && $home !== '') {
        $home = rtrim($home, DIRECTORY_SEPARATOR);
        $candidates[] = $home . '/.config/ImageMagick/policy.xml';
        $candidates[] = $home . '/.config/ImageMagick-7/policy.xml';
    }

    $configuredPath = getenv('MAGICK_CONFIGURE_PATH');
    if (is_string($configuredPath) && $configuredPath !== '') {
        foreach (explode(PATH_SEPARATOR, $configuredPath) as $directory) {
            if ($directory !== '') {
                $candidates[] = rtrim($directory, DIRECTORY_SEPARATOR) . '/policy.xml';
            }
        }
    }

    foreach (array_unique($candidates) as $candidate) {
        if (is_link($candidate) || !is_file($candidate)) {
            continue;
        }

        $result['candidate_found'] = true;
        if (is_readable($candidate)) {
            $result['candidate_readable'] = true;
            $result['paths'][] = $candidate;
        }
    }

    return $result;
}

function runSecurityDiagnostic(): array
{
    $diagnostic = [
        'imagick' => extension_loaded('imagick'),
        'zip' => class_exists('ZipArchive'),
        'imagick_version' => 'Unavailable',
        'resource_limits' => false,
        'heic_coder' => false,
        'policy' => null,
        'warnings' => [],
    ];

    if (!$diagnostic['imagick']) {
        $diagnostic['warnings'][] = 'Imagick PHP extension is unavailable.';
    } else {
        try {
            $version = Imagick::getVersion();
            $diagnostic['imagick_version'] = $version['versionString'] ?? 'Unknown';
            configureImagick();
            $diagnostic['resource_limits'] = true;
            $diagnostic['heic_coder'] = !empty(Imagick::queryFormats('HEIC'));

            if (!$diagnostic['heic_coder']) {
                $diagnostic['warnings'][] = 'ImageMagick HEIC coder is unavailable.';
            }
        } catch (Throwable $e) {
            $diagnostic['warnings'][] = 'Imagick initialization or resource configuration failed.';
            logGallery('Startup Imagick diagnostic: ' . $e->getMessage());
        }
    }

    if (!$diagnostic['zip']) {
        $diagnostic['warnings'][] = 'ZipArchive is unavailable; Download all is disabled.';
    }

    $diagnostic['policy'] = inspectImageMagickPolicy();
    $diagnostic['warnings'][] =
        'ImageMagick remote/network access restrictions cannot be verified by this application.';

    if (!$diagnostic['policy']['candidate_found']) {
        $diagnostic['warnings'][] =
            'No conventional user-level policy.xml was detected. A provider-level policy may still exist.';
    } elseif (!$diagnostic['policy']['candidate_readable']) {
        $diagnostic['warnings'][] =
            'A candidate user-level policy.xml was found but is not readable.';
    } else {
        $diagnostic['warnings'][] =
            'A user-level policy.xml was found, but loading and enforcement cannot be confirmed.';
    }

    foreach ($diagnostic['warnings'] as $warning) {
        logGallery($warning);
    }

    return $diagnostic;
}

$securityDiagnostic = runSecurityDiagnostic();

// --------------------------------------------------------------------------
// ATOMIC IMAGE CACHE WRITING
// --------------------------------------------------------------------------

function cacheImage(
    string $source,
    string $destination,
    string $format,
    bool $thumbnail = false
): bool {
    global $cacheImages, $cacheConverted;

    $allowedDirectories = [realpath($cacheImages), realpath($cacheConverted)];
    $destinationDirectory = realpath(dirname($destination));

    if (
        $destinationDirectory === false ||
        !in_array($destinationDirectory, $allowedDirectories, true) ||
        !preg_match('/^[a-f0-9]{64}\.(jpg|png)$/', basename($destination)) ||
        !in_array($format, ['jpg', 'png'], true)
    ) {
        logGallery('Rejected invalid cache destination.');
        return false;
    }

    if (is_link($destination) || (file_exists($destination) && !is_file($destination))) {
        return false;
    }

    if (is_file($destination) && filesize($destination) > 0) {
        return true;
    }

    $lockPath = $destination . '.lock';
    $lock = @fopen($lockPath, 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        if (is_resource($lock)) {
            fclose($lock);
        }
        return false;
    }

    $temp = null;
    $image = null;
    $conversionSlot = false;

    try {
        if (is_file($destination) && filesize($destination) > 0) {
            return true;
        }

        $conversionSlot = acquireConversionSlot();
        if ($conversionSlot === false) {
            logGallery('Conversion capacity is busy; request was not queued.');
            return false;
        }

        $image = loadHeif($source);

        if ($thumbnail) {
            $image->thumbnailImage(THUMBNAIL_SIZE, THUMBNAIL_SIZE, true, true);
        }

        if ($format === 'jpg') {
            $image->setImageBackgroundColor('white');
            $flattened = $image->mergeImageLayers(Imagick::LAYERMETHOD_FLATTEN);
            $image->clear();
            $image->destroy();
            $image = $flattened;
            $image->setImageFormat('jpeg');
            $image->setImageCompressionQuality($thumbnail ? 82 : 92);
        } else {
            $image->setImageFormat('png');
            $image->setImageCompressionQuality(90);
        }

        $image->stripImage();
        $temp = $destinationDirectory . '/' . bin2hex(random_bytes(12)) . '.tmp';

        if (!$image->writeImage($temp)) {
            throw new RuntimeException('Image output could not be written.');
        }

        $image->clear();
        $image->destroy();
        $image = null;

        if (
            !is_file($temp) ||
            filesize($temp) < 1 ||
            filesize($temp) > MAX_GENERATED_IMAGE_BYTES
        ) {
            throw new RuntimeException('Generated image is empty or exceeds the output size limit.');
        }

        $check = new Imagick();
        try {
            if (!$check->pingImage($temp)) {
                throw new RuntimeException('Generated image could not be inspected.');
            }

            $expected = $format === 'jpg' ? 'JPEG' : 'PNG';
            if (strtoupper($check->getImageFormat()) !== $expected) {
                throw new RuntimeException('Generated image format is unexpected.');
            }
        } finally {
            $check->clear();
            $check->destroy();
        }

        if (!@rename($temp, $destination)) {
            throw new RuntimeException('Could not publish image cache.');
        }

        $temp = null;
        @chmod($destination, 0600);
        return true;
    } catch (Throwable $e) {
        logGallery('Image processing failed: ' . $e->getMessage());
        return false;
    } finally {
        if ($image instanceof Imagick) {
            $image->clear();
            $image->destroy();
        }
        if ($temp !== null && is_file($temp)) {
            @unlink($temp);
        }
        if (is_resource($conversionSlot)) {
            flock($conversionSlot, LOCK_UN);
            fclose($conversionSlot);
        }
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

// --------------------------------------------------------------------------
// DOWNLOAD RESPONSE
// --------------------------------------------------------------------------

function sendDownload(string $path, string $filename, string $mime): never
{
    if (!isRegularFile($path) || !is_readable($path)) {
        http_response_code(404);
        exit('File unavailable.');
    }

    $size = filesize($path);
    if ($size === false) {
        http_response_code(404);
        exit('File unavailable.');
    }

    $ascii = preg_replace('/[^A-Za-z0-9._-]/', '_', $filename);
    $ascii = $ascii ?: 'download';

    header('Content-Type: ' . $mime);
    header(
        'Content-Disposition: attachment; filename="' . $ascii .
        '"; filename*=UTF-8\'\'' . rawurlencode($filename)
    );
    header('Content-Length: ' . $size);
    header('Cache-Control: private, no-store, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');

    readfile($path);
    exit;
}

// --------------------------------------------------------------------------
// THUMBNAIL REQUEST
// --------------------------------------------------------------------------

if (isset($_GET['thumb'])) {
    $key = (string) $_GET['thumb'];
    if (!preg_match('/^[a-f0-9]{64}$/', $key)) {
        http_response_code(400);
        exit;
    }

    $path = $cacheImages . '/' . $key . '.jpg';
    if (!isRegularFile($path) || !insideRoot($path)) {
        http_response_code(404);
        exit;
    }

    header('Content-Type: image/jpeg');
    header('Cache-Control: public, max-age=31536000, immutable');
    header('X-Content-Type-Options: nosniff');
    readfile($path);
    exit;
}

// --------------------------------------------------------------------------
// CONVERTED IMAGE DOWNLOAD
// --------------------------------------------------------------------------

if (isset($_GET['convert'], $_GET['format'])) {
    $relative = (string) $_GET['convert'];
    $format = strtolower((string) $_GET['format']);

    if (!in_array($format, ['jpg', 'png'], true)) {
        http_response_code(400);
        exit('Unsupported format.');
    }

    $source = safeMediaPath($relative);
    if ($source === false) {
        http_response_code(404);
        exit('Image unavailable.');
    }

    $extension = strtolower(pathinfo($source, PATHINFO_EXTENSION));
    if (!in_array($extension, IMAGE_EXTENSIONS, true)) {
        http_response_code(400);
        exit('Unsupported source format.');
    }

    $stat = @stat($source);
    if ($stat === false) {
        http_response_code(404);
        exit('Image unavailable.');
    }

    $key = hash('sha256', implode('|', [
        $relative, $stat['size'], $stat['mtime'], $stat['ino'], $format,
    ]));

    $destination = $cacheConverted . '/' . $key . '.' . $format;
    if (!cacheImage($source, $destination, $format)) {
        http_response_code(500);
        exit('Conversion failed. Check server logs.');
    }

    sendDownload(
        $destination,
        pathinfo($source, PATHINFO_FILENAME) . '.' . $format,
        $format === 'jpg' ? 'image/jpeg' : 'image/png'
    );
}

// --------------------------------------------------------------------------
// SCAN MEDIA
// --------------------------------------------------------------------------

$files = [];

$visitedEntries = 0;
$scanLimitExceeded = false;
$directory = new RecursiveDirectoryIterator(
    $root,
    FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
);
$filtered = new RecursiveCallbackFilterIterator(
    $directory,
    static function (SplFileInfo $entry, string $key, RecursiveDirectoryIterator $iterator) use (&$visitedEntries, &$scanLimitExceeded): bool {
        $visitedEntries++;
        if ($visitedEntries > MAX_SCAN_ENTRIES) {
            $scanLimitExceeded = true;
            return false;
        }
        if ($entry->isLink()) {
            return false;
        }
        if ($entry->isDir() && $entry->getFilename() === '_files') {
            return false;
        }
        return true;
    }
);
$iterator = new RecursiveIteratorIterator(
    $filtered,
    RecursiveIteratorIterator::LEAVES_ONLY,
    RecursiveIteratorIterator::CATCH_GET_CHILD
);
$iterator->setMaxDepth(MAX_SCAN_DEPTH);

try {
foreach ($iterator as $file) {

    if ($file->isLink() || !$file->isFile()) {
        continue;
    }

    $absolute = $file->getPathname();
    if (!insideRoot($absolute)) {
        continue;
    }

    $relative = str_replace(
        DIRECTORY_SEPARATOR,
        '/',
        substr($absolute, strlen($root) + 1)
    );

    if ($relative === '_files' || str_starts_with($relative, '_files/')) {
        continue;
    }

    if (realpath($absolute) === realpath(__FILE__)) {
        continue;
    }

    $extension = strtolower($file->getExtension());
    if (
        !in_array($extension, IMAGE_EXTENSIONS, true) &&
        !in_array($extension, VIDEO_EXTENSIONS, true)
    ) {
        continue;
    }

    $stat = @stat($absolute);
    if ($stat === false) {
        continue;
    }

    if (count($files) >= MAX_SCAN_MEDIA_FILES) {
        throw new RuntimeException('Gallery media-file limit exceeded. Reduce the collection size.');
    }

    $type = in_array($extension, IMAGE_EXTENSIONS, true) ? 'image' : 'video';
    $thumbnail = null;

    if ($type === 'image' && $stat['size'] <= MAX_IMAGE_FILE_SIZE) {
        $key = hash('sha256', implode('|', [
            $relative, $stat['size'], $stat['mtime'], $stat['ino'], 'thumb',
        ]));

        $destination = $cacheImages . '/' . $key . '.jpg';
        if (!is_file($destination)) {
            cacheImage($absolute, $destination, 'jpg', true);
        }

        if (isRegularFile($destination)) {
            $thumbnail = $key;
        }
    }

    $files[] = [
        'path' => $relative,
        'type' => $type,
        'thumbnail' => $thumbnail,
        'size' => $stat['size'],
        'mtime' => $stat['mtime'],
        'inode' => $stat['ino'],
    ];
}
if ($scanLimitExceeded) {
    throw new RuntimeException('Gallery scan entry limit exceeded. Reduce the number of files and folders.');
}
} catch (Throwable $e) {
    logGallery('Media scan stopped: ' . $e->getMessage());
    http_response_code(503);
    exit('Gallery is too large to scan safely. Reduce the number of files and folders.');
}

usort($files, fn($a, $b) => strnatcasecmp($a['path'], $b['path']));

// --------------------------------------------------------------------------
// CACHED ZIP DOWNLOAD
// --------------------------------------------------------------------------

if (isset($_GET['download']) && $_GET['download'] === 'all') {
    if (!class_exists('ZipArchive')) {
        http_response_code(500);
        exit('PHP ZipArchive extension unavailable.');
    }

    if (!$files) {
        http_response_code(404);
        exit('No media files found.');
    }

    $totalZipBytes = 0;
    if (count($files) > MAX_ZIP_FILES) {
        http_response_code(413);
        exit('The collection contains too many files for a single ZIP download.');
    }
    foreach ($files as $file) {
        if ($file['size'] < 0 || $file['size'] > MAX_ZIP_TOTAL_BYTES - $totalZipBytes) {
            http_response_code(413);
            exit('The collection exceeds the configured ZIP size limit.');
        }
        $totalZipBytes += $file['size'];
    }

    $fingerprint = [];
    foreach ($files as $file) {
        $fingerprint[] = implode('|', [
            $file['path'], $file['size'], $file['mtime'], $file['inode'],
        ]);
    }

    $key = hash('sha256', implode("\n", $fingerprint));
    $zipPath = $cacheZip . '/' . $key . '.zip';
    $lockPath = $zipPath . '.lock';
    $lock = @fopen($lockPath, 'c');

    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        if (is_resource($lock)) {
            fclose($lock);
        }
        http_response_code(503);
        exit('A ZIP request for this collection is already being processed. Retry shortly.');
    }

    $zipBuildLock = false;
    try {
        if (!is_file($zipPath) || filesize($zipPath) < 1) {
            $zipBuildLock = @fopen($storage . '/zip-build.lock', 'c');
            if ($zipBuildLock === false || !@flock($zipBuildLock, LOCK_EX | LOCK_NB)) {
                if (is_resource($zipBuildLock)) {
                    fclose($zipBuildLock);
                }
                $zipBuildLock = false;
                throw new RuntimeException('Another ZIP archive is currently being generated. Retry shortly.');
            }

            $temp = $cacheZip . '/' . bin2hex(random_bytes(12)) . '.tmp';
            $zip = new ZipArchive();

            if ($zip->open($temp, ZipArchive::CREATE | ZipArchive::EXCL) !== true) {
                throw new RuntimeException('Cannot create ZIP archive.');
            }

            $added = 0;
            foreach ($files as $file) {
                $source = safeMediaPath($file['path']);
                if ($source === false) {
                    throw new RuntimeException('A media file became unavailable.');
                }

                clearstatcache(true, $source);
                $current = @stat($source);
                if (
                    $current === false ||
                    $current['size'] !== $file['size'] ||
                    $current['mtime'] !== $file['mtime'] ||
                    $current['ino'] !== $file['inode']
                ) {
                    throw new RuntimeException('Media collection changed; please retry.');
                }

                if (!$zip->addFile($source, $file['path'])) {
                    throw new RuntimeException('Could not add a media file to ZIP.');
                }
                $added++;
            }

            if ($added !== count($files) || !$zip->close()) {
                @unlink($temp);
                throw new RuntimeException('ZIP creation failed.');
            }

            if (
                !is_file($temp) ||
                filesize($temp) < 1 ||
                filesize($temp) > MAX_ZIP_TOTAL_BYTES + (16 * 1024 * 1024) ||
                !@rename($temp, $zipPath)
            ) {
                @unlink($temp);
                throw new RuntimeException('Could not publish ZIP cache.');
            }

            @chmod($zipPath, 0600);
        }
    } catch (Throwable $e) {
        if (isset($zip) && $zip instanceof ZipArchive) {
            @$zip->close();
        }
        if (is_resource($zipBuildLock)) {
            flock($zipBuildLock, LOCK_UN);
            fclose($zipBuildLock);
        }
        if (isset($temp) && is_file($temp)) {
            @unlink($temp);
        }

        logGallery('ZIP generation failed: ' . $e->getMessage());
        flock($lock, LOCK_UN);
        fclose($lock);
        http_response_code(503);
        exit('ZIP creation failed or another archive is being generated. Check server logs and retry.');
    }

    if (is_resource($zipBuildLock)) {
        flock($zipBuildLock, LOCK_UN);
        fclose($zipBuildLock);
    }
    flock($lock, LOCK_UN);
    fclose($lock);
    sendDownload($zipPath, 'media-gallery.zip', 'application/zip');
}

// --------------------------------------------------------------------------
// URL HELPER
// --------------------------------------------------------------------------

function fileUrl(string $path): string
{
    return implode('/', array_map('rawurlencode', explode('/', $path)));
}

// --------------------------------------------------------------------------
// HTML GALLERY
// --------------------------------------------------------------------------

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Media Gallery</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    padding: 24px;
    background: #171717;
    color: #eee;
    font-family: system-ui, sans-serif;
}
header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 24px;
    flex-wrap: wrap;
}
h1 { font-size: 1.5rem; margin: 0; }
a { color: inherit; }
.download, .convert, .video-download {
    display: inline-block;
    padding: 9px 13px;
    color: white;
    text-decoration: none;
    border-radius: 6px;
    font-size: .85rem;
    font-weight: 600;
}
.download, .video-download { background: #3478f6; }
.convert { background: #444; }
.download:hover, .video-download:hover { background: #2563d9; }
.convert:hover { background: #606060; }
.gallery {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 20px;
}
.item {
    min-width: 0;
    background: #252525;
    border-radius: 8px;
    overflow: hidden;
}
.item img, .item video {
    display: block;
    width: 100%;
    height: 240px;
    object-fit: contain;
    background: #000;
}
.filename {
    padding: 10px 12px;
    font-size: .85rem;
    overflow-wrap: anywhere;
    color: #ccc;
}
.actions {
    display: flex;
    gap: 8px;
    padding: 0 12px 12px;
    flex-wrap: wrap;
}
.thumbnail-error {
    height: 240px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #111;
    color: #888;
}
.empty { color: #aaa; }
.security-warning {
    margin: 0 0 20px;
    padding: 12px 14px;
    border: 1px solid #8a6428;
    border-radius: 6px;
    background: #382b18;
    color: #f1d7a7;
    font-size: .9rem;
    line-height: 1.5;
}
.security-warning strong { display: block; margin-bottom: 4px; }
@media (max-width: 600px) {
    body { padding: 16px; }
    .gallery { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<header>
    <h1>Media Gallery</h1>
    <?php if ($files): ?>
        <a class="download" href="?download=all">
            Download all originals (<?= count($files) ?>)
        </a>
    <?php endif; ?>
</header>

<?php if (SHOW_SECURITY_WARNING && $securityDiagnostic['warnings']): ?>
    <aside class="security-warning" role="status">
        <strong>Security configuration notice</strong>
        ImageMagick's remote/network access restrictions could not be verified.
        A policy file may be present, but this application cannot confirm that
        ImageMagick loaded or enforces it. Consult the hosting provider's
        ImageMagick configuration documentation. Technical details are in the
        PHP error log. You can disable this notice by setting
        SHOW_SECURITY_WARNING to false in index.php.
    </aside>
<?php endif; ?>

<?php if (!$files): ?>
    <p class="empty">No HEIC, HEIF or MOV files found.</p>
<?php else: ?>
<div class="gallery">
<?php foreach ($files as $file): ?>
    <?php
        $path = $file['path'];
        $url = fileUrl($path);
        $downloadName = basename($path);
    ?>
    <div class="item">
        <?php if ($file['type'] === 'image'): ?>
            <?php if ($file['thumbnail']): ?>
                <a href="<?= h($url) ?>" target="_blank" rel="noopener noreferrer">
                    <img
                        src="?thumb=<?= h($file['thumbnail']) ?>"
                        alt="<?= h($path) ?>"
                        loading="lazy"
                    >
                </a>
            <?php else: ?>
                <div class="thumbnail-error">Thumbnail unavailable</div>
            <?php endif; ?>
        <?php else: ?>
            <video controls preload="metadata">
                <source src="<?= h($url) ?>" type="video/quicktime">
                Your browser cannot play this video format.
            </video>
        <?php endif; ?>

        <div class="filename"><?= h($path) ?></div>

        <?php if ($file['type'] === 'image'): ?>
            <div class="actions">
                <a class="convert" href="?convert=<?= rawurlencode($path) ?>&amp;format=jpg">Download JPG</a>
                <a class="convert" href="?convert=<?= rawurlencode($path) ?>&amp;format=png">Download PNG</a>
                <a class="convert" href="<?= h($url) ?>" download="<?= h($downloadName) ?>">Download original</a>
            </div>
        <?php else: ?>
            <div class="actions">
                <a class="video-download" href="<?= h($url) ?>" download="<?= h($downloadName) ?>">Download video</a>
            </div>
        <?php endif; ?>
    </div>
<?php endforeach; ?>
</div>
<?php endif; ?>

</body>
</html>
