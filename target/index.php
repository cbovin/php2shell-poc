<?php
header("Content-Type: text/plain; charset=UTF-8");

$proof = "/out/p1";
if (!is_file($proof)) {
    echo "php-lab\n";
    exit;
}

echo "php-lab: updated by the PoC\n";
echo trim((string) file_get_contents($proof)), "\n";
