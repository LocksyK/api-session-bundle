<?php

declare(strict_types=1);

$finder = (new PhpCsFixer\Finder())
    ->in([__DIR__.'/src', __DIR__.'/tests', __DIR__.'/config'])
;

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@Symfony' => true,
        '@Symfony:risky' => true,
        'declare_strict_types' => true,
        'header_comment' => [
            'header' => <<<'HEADER'
                This file is part of the ApiSessionBundle package.

                (c) Kris Shannon <kris@shannon.id.au>

                This program is free software; you can redistribute it and/or modify it
                under the terms of the GNU General Public License version 2 as published
                by the Free Software Foundation.
                HEADER,
        ],
    ])
    ->setFinder($finder)
;
