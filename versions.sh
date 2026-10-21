#!/bin/sh

select_php_version() {
    PHP_LAB_VERSION=${1:-8.4.26}

    case "$PHP_LAB_VERSION" in
        8.2.34)
            PHP_IMAGE='php:8.2.34-apache@sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86'
            ;;
        8.3.35)
            PHP_IMAGE='php:8.3.35-apache@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184'
            ;;
        8.4.26)
            PHP_IMAGE='php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a'
            ;;
        8.5.11)
            PHP_IMAGE='php:8.5.11-apache@sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b'
            ;;
        *)
            printf '%s\n' \
                "ERROR: unsupported PHP version: $PHP_LAB_VERSION" \
                'Supported: 8.2.34, 8.3.35, 8.4.26, 8.5.11' >&2
            return 1
            ;;
    esac

    export PHP_LAB_VERSION PHP_IMAGE
}
