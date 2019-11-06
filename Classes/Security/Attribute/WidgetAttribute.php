<?php
declare(strict_types = 1);

namespace FriendsOfTYPO3\Dashboard\Security\Attribute;

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

use TYPO3\CMS\Backend\Security\Attribute\ResourceAttribute;
use TYPO3\CMS\Security\Utility\AttributeUtility;

/**
 * @api
 */
final class WidgetAttribute extends ResourceAttribute
{
    /**
     * @var DashboardAttribute
     */
    public $dashboard;

    /**
     * @var string
     */
    public $type;

    /**
     * @inheritdoc
     */
    public function __construct(string $type, string $identifier, DashboardAttribute $dashboard)
    {
        parent::__construct($identifier);
        $this->dashboard = $dashboard;
        $this->type = $this->class . ':' . AttributeUtility::translateClassNameToPolicyName($type);
        $this->identifier = $this->class . ':' . $identifier;
    }
}
