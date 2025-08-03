<?php
declare(strict_types=1);
header("Content-Type: text/plain");
/**
 * This script demonstrates the usage of the G3FC library via PHP FFI.
 * It provides a simple command-line interface to test the library's functionality.
 * 
 * Requirements:
 * - PHP with FFI extension enabled
 * - Compiled G3FC library available at the specified path
 * - Write permissions to the temporary directory
 */

// --- CONFIGURATION ---
// Change this path to the location of your compiled library.
// Linux: 'target/release/libg3fc.so'
// Windows: 'target/release/g3fc.dll'
// macOS: 'target/release/libg3fc.dylib'
const G3FC_LIB_PATH = '/libg3fc/target/release/libg3fc.so';

// Temporary directory to create test files.
const TEMP_DIR = __DIR__ . '/g3fc_test';

// Check if the FFI extension is available.
if (!extension_loaded('FFI')) {
    die('PHP FFI extension is not enabled. Please enable it in your php.ini file.');
}

if (!file_exists(G3FC_LIB_PATH)) {
    die('Error: Library file not found at: ' . G3FC_LIB_PATH . "\nPlease compile the Rust project first with 'cargo build --release'.\n");
}


/**
 * A wrapper class to interact with the native G3FC library.
 * It encapsulates the FFI logic and error handling.
 */
class G3FCNative
{
    private FFI $ffi;
    private string $libraryPath;

    public function __construct(string $libraryPath)
    {
        $this->libraryPath = $libraryPath;
        $this->ffi = FFI::cdef(
            // Definition of the library's interface (C header).
            // This must exactly match the `extern "C"` functions in Rust.
            "
            // Action Functions (return int32_t status: 0 for success, -1 for error)
            int32_t g3fc_create_archive(const char* json_args);
            int32_t g3fc_extract_archive(const char* archive_path, const char* output_dir, const char* password);
            int32_t g3fc_extract_single(const char* archive_path, const char* file_in_archive, const char* output_dir, const char* password);

            // Query Functions (return char* string pointer: JSON on success, NULL on error)
            char* g3fc_list_files(const char* archive_path, const char* password);
            char* g3fc_info_export_json(const char* archive_path, const char* password);
            char* g3fc_find_files(const char* archive_path, const char* pattern, const char* password, bool is_regex);

            // Utility Functions (error and memory management)
            char* g3fc_last_error_message();
            void g3fc_free_string(char* s);
            ",
            $this->libraryPath
        );
    }

    /**
     * Gets the last error message from the library.
     */
    private function getLastError(): string
    {
        $errorPtr = $this->ffi->g3fc_last_error_message();
        if ($errorPtr === null) {
            return 'An unknown error occurred in the native library.';
        }
        $errorMessage = FFI::string($errorPtr);
        $this->ffi->g3fc_free_string($errorPtr); // Free the error string
        return $errorMessage;
    }
    
    /**
     * Executes an action function that returns a status code.
     * Throws an exception on failure.
     */
    private function executeAction(callable $action): void
    {
        $status = $action();
        if ($status !== 0) {
            throw new RuntimeException($this->getLastError());
        }
    }

    /**
     * Executes a query function that returns a string pointer.
     * Returns the decoded array or throws an exception.
     */
    private function executeQuery(callable $query): ?array
    {
        $resultPtr = $query();
        if ($resultPtr === null) {
            throw new RuntimeException($this->getLastError());
        }
        $jsonString = FFI::string($resultPtr);
        $this->ffi->g3fc_free_string($resultPtr); // Free the result string
        return json_decode($jsonString, true);
    }

    // --- PUBLIC API METHODS ---

    /**
     * Creates an archive from a set of files and folders.
     * // C Header: int32_t g3fc_create_archive(const char* json_args);
     */
    public function createArchive(array $args): void
    {
        $jsonArgs = json_encode($args);
        $this->executeAction(fn() => $this->ffi->g3fc_create_archive($jsonArgs));
    }

    /**
     * Extracts all contents of an archive to a directory.
     * // C Header: int32_t g3fc_extract_archive(const char* archive_path, const char* output_dir, const char* password);
     */
    public function extractArchive(string $archivePath, string $outputDir, ?string $password = null): void
    {
        $this->executeAction(fn() => $this->ffi->g3fc_extract_archive($archivePath, $outputDir, $password));
    }

    /**
     * Extracts a single file from an archive to a directory.
     * // C Header: int32_t g3fc_extract_single(const char* archive_path, const char* file_in_archive, const char* output_dir, const char* password);
     */
    public function extractSingleFile(string $archivePath, string $fileInArchive, string $outputDir, ?string $password = null): void
    {
        $this->executeAction(fn() => $this->ffi->g3fc_extract_single($archivePath, $fileInArchive, $outputDir, $password));
    }
    
    /**
     * Lists the logical files inside an archive.
     * // C Header: char* g3fc_list_files(const char* archive_path, const char* password);
     */
    public function listFiles(string $archivePath, ?string $password = null): ?array
    {
        return $this->executeQuery(fn() => $this->ffi->g3fc_list_files($archivePath, $password));
    }

    /**
     * Gets the full, detailed metadata index from the archive.
     * // C Header: char* g3fc_info_export_json(const char* archive_path, const char* password);
     */
    public function getInfo(string $archivePath, ?string $password = null): ?array
    {
        return $this->executeQuery(fn() => $this->ffi->g3fc_info_export_json($archivePath, $password));
    }

    /**
     * Finds files within the archive that match a given pattern.
     * // C Header: char* g3fc_find_files(const char* archive_path, const char* pattern, bool is_regex, const char* password);
     */
    public function findFiles(string $archivePath, string $pattern, ?string $password = null, bool $isRegex = false): ?array
    {
        return $this->executeQuery(fn() => $this->ffi->g3fc_find_files($archivePath, $pattern, $password, $isRegex));
    }
}


/**
 * Main function to run the demonstration.
 */
function main()
{
    echo "🚀 Starting G3FC library demonstration...\n\n";

    // Prepare the test environment
    if (is_dir(TEMP_DIR)) {
        // Clean up previous test directory
        system('rm -rf ' . escapeshellarg(TEMP_DIR));
    }
    mkdir(TEMP_DIR, 0777, true);
    file_put_contents(TEMP_DIR . '/file1.txt', 'This is the first file.');
    mkdir(TEMP_DIR . '/subdir');
    file_put_contents(TEMP_DIR . '/subdir/file2.log', 'A test log.');
    echo "✓ Test environment prepared at: " . TEMP_DIR . "\n";
    
    $archiveFile = TEMP_DIR . '/my_archive.g3fc';
    $extractDir = TEMP_DIR . '/extracted';
    $password = 'super-secret-password-123';

    try {
        $g3fc = new G3FCNative(G3FC_LIB_PATH);

        // 1. Create an archive
        echo "--- 1. Creating archive '{$archiveFile}' ---\n";
        $g3fc->createArchive([
            'input_paths' => [TEMP_DIR . '/file1.txt', TEMP_DIR . '/subdir'],
            'output' => $archiveFile,
            'password' => $password,
            'compression_level' => 12,
        ]);
        echo "✓ Archive created successfully!\n\n";
        
        // 2. List the archive contents
        echo "--- 2. Listing archive contents ---\n";
        $files = $g3fc->listFiles($archiveFile, $password);
        print_r($files);
        echo "\n";

        // 3. Get detailed info (Info)
        echo "--- 3. Getting detailed archive info ---\n";
        $info = $g3fc->getInfo($archiveFile, $password);
        echo "Total chunks/entries in index: " . count($info) . "\n";
        echo "First entry: " . ($info[0]['Path'] ?? 'N/A') . "\n\n";

        // 4. Find files (Find)
        echo "--- 4. Finding files with pattern '.log' ---\n";
        $found = $g3fc->findFiles($archiveFile, '\.log$', $password, true);
        print_r($found);
        echo "\n";

        // 5. Extract a single file
        echo "--- 5. Extracting single file 'subdir/file2.log' ---\n";
        $g3fc->extractSingleFile($archiveFile, 'subdir/file2.log', $extractDir, $password);
        echo "✓ File extracted to: {$extractDir}/subdir/file2.log\n";
        echo "Content: " . file_get_contents($extractDir . '/subdir/file2.log') . "\n\n";

        // 6. Extract the full archive
        echo "--- 6. Extracting full archive ---\n";
        $g3fc->extractArchive($archiveFile, $extractDir, $password);
        echo "✓ Full archive extracted to: " . $extractDir . "\n";
        echo "Checking extracted file: " . (file_exists($extractDir . '/file1.txt') ? 'OK' : 'FAILED') . "\n\n";
        
        echo "✅ Demonstration completed successfully!\n";

    } catch (Throwable $e) {
        echo "\n❌ ERROR DURING EXECUTION:\n";
        echo "================================\n";
        echo $e->getMessage() . "\n";
        echo "File: " . $e->getFile() . " (Line: " . $e->getLine() . ")\n";
        echo "================================\n";
        exit(1);
    } finally {
        // Clean up the test files
        if (is_dir(TEMP_DIR)) {
            // system('rm -rf ' . escapeshellarg(TEMP_DIR));
            // echo "\n🧹 Test environment cleaned up.\n";
        }
    }
}

// Run the script
main();
