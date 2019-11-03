<?php
declare(strict_types = 1);

namespace FriendsOfTYPO3\Dashboard\Security\Permission;

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

use FriendsOfTYPO3\Dashboard\Security\Attribute\ViewAttribute;
use FriendsOfTYPO3\Dashboard\Security\Attribute\WidgetAttribute;
use TYPO3\CMS\Backend\Security\Attribute\GroupAttribute;
use TYPO3\CMS\Backend\Security\Attribute\PermissionAttribute;
use TYPO3\CMS\Backend\Security\Attribute\UserAttribute;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Security\Event\AttributeRetrivalEvent;
use TYPO3\CMS\Security\Utility\AttributeUtility;

/**
 * @internal
 */
class PermissionAttributeProvider
{
    /**
     * @var FrontendInterface
     */
    private $cache;

    public function __construct(FrontendInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * @inheritdoc
     */
    public function __invoke(AttributeRetrivalEvent $event): void
    {
        if (!$event->getAttribute() instanceof WidgetAttribute) {
            return;
        }

        if (!$event->getContext()->getAspect('backend.user')->get('isLoggedIn')) {
            return;
        }

        $attribute = $event->getAttribute();
        $userAspect = $event->getContext()->getAspect('backend.user');
        $cacheIdentifier = sha1(static::class . '_user_permissions' . $userAspect->get('id'));

        if (($entry = $this->cache->get($cacheIdentifier)) === false) {
            $entry = [];

            // @TODO: Collect all resource related permissions of the current subject principals (user, group and roles)
            if ($attribute->type === 'dashboard:widget:t3-news') {
                $entry[] = new PermissionAttribute(
                    new UserAttribute(1, 'admin'),
                    $attribute->type,
                    AttributeUtility::translateClassNameToPolicyName(ViewAttribute::class),
                    PermissionAttribute::STATE_DENY
                );
                $entry[] = new PermissionAttribute(
                    new GroupAttribute(1, 'Administrators'),
                    $attribute->type,
                    AttributeUtility::translateClassNameToPolicyName(ViewAttribute::class),
                    PermissionAttribute::STATE_PERMIT
                );
                $entry[] = new PermissionAttribute(
                    new UserAttribute(1, 'admin'),
                    $attribute->identifier,
                    AttributeUtility::translateClassNameToPolicyName(ViewAttribute::class),
                    PermissionAttribute::STATE_PERMIT
                );
            }

            $this->cache->set($cacheIdentifier, $entry);
        }

        $attribute->permissions = array_merge($attribute->permissions, $entry);
    }
}
