<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $inputText = $_POST['inputText'] ?? '';  // Handle empty input text
    $key = $_POST['key'] ?? '';              // Handle empty key
    $cipherType = $_POST['cipherType'] ?? ''; // Get selected cipher type
    $operation = $_POST['operation'] ?? '';   // Encrypt or Decrypt

    // Handle file upload if provided
    if (isset($_FILES['file']) && $_FILES['file']['error'] == UPLOAD_ERR_OK) {
        $inputText = file_get_contents($_FILES['file']['tmp_name']);
    }

    // Process encryption/decryption based on selected cipher
    switch ($cipherType) {
        case 'vigenere':
            if ($operation == 'encrypt') {
                $result = vigenereEncrypt($inputText, $key);
            } else {
                $result = vigenereDecrypt($inputText, $key);
            }
            break;
        case 'autoKeyVigenere':
            if ($operation == 'encrypt') {
                $result = autoKeyVigenereEncrypt($inputText, $key);
            } else {
                $result = autoKeyVigenereDecrypt($inputText, $key);
            }
            break;
        case 'playfair':
            if ($operation == 'encrypt') {
                $result = playfairEncrypt($inputText, $key);
            } else {
                $result = playfairDecrypt($inputText, $key);
            }
            break;
        case 'hill':
            if ($operation == 'encrypt') {
                $result = hillEncrypt($inputText, $key);
            } else {
                $result = hillDecrypt($inputText, $key);
            }
            break;
        case 'super':
            if ($operation == 'encrypt') {
                $result = superEncrypt($inputText, $key);
            } else {
                $result = superDecrypt($inputText, $key);
            }
            break;
        default:
            $result = "Invalid cipher type selected.";
            break;
    }

    // Save result to file
    $fileName = "cipher_text.txt"; // Name of the file
    saveToFile($result, $fileName); // Call function to save

    // Return the result as a JSON response
    echo json_encode([
        'outputText' => base64_encode($result),  // Encode output as base64 for safety
        'fileName' => $fileName // Return the name of the file
    ]);
}

// Function to save text to a file
function saveToFile($content, $fileName) {
    file_put_contents($fileName, $content);
}

// Vigenère Cipher
function vigenereEncrypt($text, $key) {
    $output = "";
    $text = strtoupper($text);
    $key = strtoupper($key);
    $keyLength = strlen($key);
    $textLength = strlen($text);

    for ($i = 0; $i < $textLength; $i++) {
        $char = $text[$i];
        if (ctype_alpha($char)) {
            $offset = (ord($char) + ord($key[$i % $keyLength]) - 2 * ord('A')) % 26;
            $output .= chr($offset + ord('A'));
        } else {
            $output .= $char;
        }
    }
    return $output;
}

function vigenereDecrypt($text, $key) {
    $output = "";
    $text = strtoupper($text);
    $key = strtoupper($key);
    $keyLength = strlen($key);
    $textLength = strlen($text);

    for ($i = 0; $i < $textLength; $i++) {
        $char = $text[$i];
        if (ctype_alpha($char)) {
            $offset = (ord($char) - ord($key[$i % $keyLength]) + 26) % 26;
            $output .= chr($offset + ord('A'));
        } else {
            $output .= $char;
        }
    }
    return $output;
}

// Auto-Key Vigenère Cipher
function autoKeyVigenereEncrypt($text, $key) {
    $key .= $text;  // Auto-key feature, key is extended by the plaintext
    return vigenereEncrypt($text, $key);
}

function autoKeyVigenereDecrypt($text, $key) {
    $output = "";
    $key = strtoupper($key);
    $text = strtoupper($text);
    $keyLength = strlen($key);

    for ($i = 0; $i < strlen($text); $i++) {
        $char = $text[$i];
        if (ctype_alpha($char)) {
            $offset = (ord($char) - ord($key[$i]) + 26) % 26;
            $decryptedChar = chr($offset + ord('A'));
            $output .= $decryptedChar;
            $key .= $decryptedChar;  // Extend key with decrypted characters
        } else {
            $output .= $char;
        }
    }
    return $output;
}

// Playfair Cipher
function playfairEncrypt($text, $key) {
    $keyMatrix = generatePlayfairMatrix($key);
    $text = strtoupper($text);
    $text = str_replace('J', 'I', $text); // Playfair combines 'I' and 'J'

    $textPairs = getPlayfairTextPairs($text);
    $encryptedText = '';

    foreach ($textPairs as $pair) {
        list($row1, $col1) = getCharPosition($keyMatrix, $pair[0]);
        list($row2, $col2) = getCharPosition($keyMatrix, $pair[1]);

        if ($row1 == $row2) {
            // Same row, shift right
            $encryptedText .= $keyMatrix[$row1][($col1 + 1) % 5];
            $encryptedText .= $keyMatrix[$row2][($col2 + 1) % 5];
        } elseif ($col1 == $col2) {
            // Same column, shift down
            $encryptedText .= $keyMatrix[($row1 + 1) % 5][$col1];
            $encryptedText .= $keyMatrix[($row2 + 1) % 5][$col2];
        } else {
            // Rectangle rule
            $encryptedText .= $keyMatrix[$row1][$col2];
            $encryptedText .= $keyMatrix[$row2][$col1];
        }
    }
    return $encryptedText;
}

function playfairDecrypt($text, $key) {
    $keyMatrix = generatePlayfairMatrix($key);
    $text = strtoupper($text);

    $textPairs = getPlayfairTextPairs($text);
    $decryptedText = '';

    foreach ($textPairs as $pair) {
        list($row1, $col1) = getCharPosition($keyMatrix, $pair[0]);
        list($row2, $col2) = getCharPosition($keyMatrix, $pair[1]);

        if ($row1 == $row2) {
            // Same row, shift left
            $decryptedText .= $keyMatrix[$row1][($col1 + 4) % 5];
            $decryptedText .= $keyMatrix[$row2][($col2 + 4) % 5];
        } elseif ($col1 == $col2) {
            // Same column, shift up
            $decryptedText .= $keyMatrix[($row1 + 4) % 5][$col1];
            $decryptedText .= $keyMatrix[($row2 + 4) % 5][$col2];
        } else {
            // Rectangle rule
            $decryptedText .= $keyMatrix[$row1][$col2];
            $decryptedText .= $keyMatrix[$row2][$col1];
        }
    }
    return $decryptedText;
}

function generatePlayfairMatrix($key) {
    $key = strtoupper($key);
    $key = str_replace('J', 'I', $key);
    $alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
    $matrix = [];
    $usedLetters = [];

    foreach (str_split($key . $alphabet) as $char) {
        if (!in_array($char, $usedLetters)) {
            $usedLetters[] = $char;
        }
    }

    for ($i = 0; $i < 5; $i++) {
        $matrix[$i] = array_slice($usedLetters, $i * 5, 5);
    }
    return $matrix;
}

function getCharPosition($matrix, $char) {
    for ($i = 0; $i < 5; $i++) {
        for ($j = 0; $j < 5; $j++) {
            if ($matrix[$i][$j] == $char) {
                return [$i, $j];
            }
        }
    }
    return null;
}

function getPlayfairTextPairs($text) {
    $pairs = [];
    $text = preg_replace('/[^A-Z]/', '', $text);
    
    for ($i = 0; $i < strlen($text); $i += 2) {
        $first = $text[$i];
        $second = ($i + 1 < strlen($text)) ? $text[$i + 1] : 'X';
        
        if ($first == $second) {
            $second = 'X';
            $i--;
        }
        $pairs[] = [$first, $second];
    }
    return $pairs;
}

// Hill Cipher (simplified 2x2 matrix)
function hillEncrypt($text, $key) {
    $text = strtoupper(preg_replace('/[^A-Z]/', '', $text));
    $matrixKey = [[3, 3], [2, 5]]; // Example key matrix (replace with dynamic if needed)
    $output = '';

    for ($i = 0; $i < strlen($text); $i += 2) {
        $x1 = ord($text[$i]) - ord('A');
        $x2 = ord($text[$i + 1]) - ord('A');
        
        $y1 = ($matrixKey[0][0] * $x1 + $matrixKey[0][1] * $x2) % 26;
        $y2 = ($matrixKey[1][0] * $x1 + $matrixKey[1][1] * $x2) % 26;

        $output .= chr($y1 + ord('A')) . chr($y2 + ord('A'));
    }
    return $output;
}

function hillDecrypt($text, $key) {
    $text = strtoupper(preg_replace('/[^A-Z]/', '', $text));
    $inverseMatrixKey = [[15, 17], [20, 9]]; // Example inverse key matrix
    $output = '';

    for ($i = 0; $i < strlen($text); $i += 2) {
        $y1 = ord($text[$i]) - ord('A');
        $y2 = ord($text[$i + 1]) - ord('A');
        
        $x1 = ($inverseMatrixKey[0][0] * $y1 + $inverseMatrixKey[0][1] * $y2) % 26;
        $x2 = ($inverseMatrixKey[1][0] * $y1 + $inverseMatrixKey[1][1] * $y2) % 26;

        $output .= chr($x1 + ord('A')) . chr($x2 + ord('A'));
    }
    return $output;
}

// Super Encryption (Vigenère + Columnar Transposition)
function superEncrypt($text, $key) {
    $vigenereEncrypted = vigenereEncrypt($text, $key);
    return columnarTranspositionEncrypt($vigenereEncrypted, $key);
}

function superDecrypt($text, $key) {
    $columnDecrypted = columnarTranspositionDecrypt($text, $key);
    return vigenereDecrypt($columnDecrypted, $key);
}

// Columnar Transposition Cipher
function columnarTranspositionEncrypt($text, $key) {
    $n = strlen($key);
    $columns = array_fill(0, $n, "");
    
    for ($i = 0; $i < strlen($text); $i++) {
        $columns[$i % $n] .= $text[$i];
    }
    
    $output = "";
    for ($i = 0; $i < $n; $i++) {
        $output .= $columns[$i];
    }
    return $output;
}

function columnarTranspositionDecrypt($text, $key) {
    $n = strlen($key);
    $rows = ceil(strlen($text) / $n);
    $grid = array_fill(0, $rows, array_fill(0, $n, ''));

    $pos = 0;
    for ($i = 0; $i < $n; $i++) {
        for ($j = 0; $j < $rows; $j++) {
            if ($pos < strlen($text)) {
                $grid[$j][$i] = $text[$pos++];
            }
        }
    }

    $output = "";
    for ($i = 0; $i < $rows; $i++) {
        for ($j = 0; $j < $n; $j++) {
            $output .= $grid[$i][$j];
        }
    }
    return $output;
}
?>
