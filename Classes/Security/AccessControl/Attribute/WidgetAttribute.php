<?php
declare(strict_types = 1);

namespace FriendsOfTYPO3\Dashboard\Security\AccessControl\Attribute;

/*
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

use TYPO3\CMS\Backend\Security\AccessControl\Attribute\ResourceAttribute;
use TYPO3\CMS\Security\AccessControl\Utility\AttributeUtility;

/**
 * @api
 */
final class WidgetAttribute extends ResourceAttribute
{
    /**
     * @inheritdoc
     */
    public function __construct(string $type, string $identifier, DashboardAttribute $dashboard)
    {
        parent::__construct($identifier);

        $this->meta['dashboard'] = $dashboard;
        $this->meta['type'] = $this->namespace . ':' . AttributeUtility::translateIdentifier($type);
    }

    public function getType(): string
    {
        return $this->meta['type'];
    }

    public function getDashboard(): DashboardAttribute
    {
        return $this->meta['dashboard'];
    }
}
