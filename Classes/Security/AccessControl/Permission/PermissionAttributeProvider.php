<?php
declare(strict_types = 1);

namespace FriendsOfTYPO3\Dashboard\Security\AccessControl\Permission;

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

use FriendsOfTYPO3\Dashboard\Security\AccessControl\Attribute\DashboardAttribute;
use FriendsOfTYPO3\Dashboard\Security\AccessControl\Attribute\WidgetAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\GroupAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\PermissionAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\UserAttribute;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Exception\InvalidArgumentException;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Security\AccessControl\Attribute\PrincipalAttribute;
use TYPO3\CMS\Security\AccessControl\Event\AttributeRetrivalEvent;
use TYPO3\CMS\Security\AccessControl\Utility\PrincipalUtility;

/**
 * @internal
 */
class PermissionAttributeProvider
{
    /**
     * @var string
     */
    private const TABLE = 'sys_dashboards';

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
        $resourceAttribute = $event->getAttribute();

        if (!$resourceAttribute instanceof WidgetAttribute && !$resourceAttribute instanceof DashboardAttribute) {
            return;
        }

        $principalAttributes = PrincipalUtility::filterList(
            $event->getSubject()->getPrincipals(),
            static function ($principal) {
                return $principal instanceof UserAttribute || $principal instanceof GroupAttribute;
            }
        );

        if (count($principalAttributes) === 0) {
            return;
        }

        ksort($principalAttributes);

        $cacheIdentifier = sha1(
            static::class 
            . '_permissions_' 
            . implode('_', array_keys($principalAttributes))
            . $resourceAttribute->getName()
        );
        $permissionAttributes = $this->cache->get($cacheIdentifier);

        if ($permissionAttributes === false) {
            $permissionAttributes = [];

            if ($resourceAttribute instanceof WidgetAttribute) {
                foreach ($this->getWidgetPermissions($resourceAttribute) as $principalIdentifier => $permissions) {
                    if (!isset($principalAttributes[$principalIdentifier])) {
                        continue;
                    }
                    foreach ($permissions as $action => $state) {
                        $permissionAttributes[] = $this->createPermissionAttribute(
                            $principalAttributes[$principalIdentifier],
                            $resourceAttribute->getName(),
                            $action,
                            $state
                        );
                    }
                }
            } else if ($resourceAttribute instanceof DashboardAttribute) {
                foreach ($this->getDashboardPermissions($resourceAttribute) as $principalIdentifier => $permissions) {
                    if (!isset($principalAttributes[$principalIdentifier])) {
                        continue;
                    }
                    foreach ($permissions as $action => $state) {
                        $permissionAttributes[] = $this->createPermissionAttribute(
                            $principalAttributes[$principalIdentifier],
                            $resourceAttribute->getName(),
                            $action,
                            $state
                        );
                    }
                }
            }

            $this->cache->set($cacheIdentifier, $permissionAttributes);
        }

        foreach ($permissionAttributes as $permissionAttribute) {
            $resourceAttribute->addPermissions($permissionAttribute);
        }
    }

    protected function createPermissionAttribute(string $principalIdentifier, string $resource, string $action, string $state): PermissionAttribute
    {
        $principalAttribute = $this->resolvePrincipalAttribute($principalIdentifier);
        return new PermissionAttribute(
            $principalAttribute,
            $resource,
            $action,
            $state
        );
    }

    /**
     * Example result:
     * [
     *      'be_user:123' => [
     *          'dashboard:view' => 'permit',
     *          'dashboard:edit' => 'deny',
     *      ]
     * ]
     * @param WidgetAttribute $widgetAttribute
     * @return array
     */
    protected function getWidgetPermissions(WidgetAttribute $widgetAttribute): array
    {
        $permissions = [];

        $rows = $this->getQueryBuilder()
            ->select('configuration')
            ->from(self::TABLE)
            ->execute()
            ->fetchAll();
        foreach ($rows as $row) {
            $configuration = json_decode($row['configuration'], true);
            foreach ($configuration['widgets'] as $widgetHash => $widgetConfiguration) {
                if ($widgetHash === $widgetAttribute->getIdentifier()) {
                    return $widgetConfiguration['permissions'] ?? [];
                }
            }
        }
        return $permissions;
    }

    /**
     * Example result:
     * [
     *      'be_user:123' => [
     *          'dashboard:view' => 'permit',
     *          'dashboard:edit' => 'deny',
     *      ]
     * ]
     * @param DashboardAttribute $dashboardAttribute
     * @return array
     */
    protected function getDashboardPermissions(DashboardAttribute $dashboardAttribute): array
    {
        $permissions = [];

        $queryBuilder = $this->getQueryBuilder();
        $rows = $queryBuilder
            ->select('configuration')
            ->from(self::TABLE)
            ->where($queryBuilder->expr()->eq(
                'identifier',
                $queryBuilder->createNamedParameter($dashboardAttribute->getIdentifier())
            ))
            ->execute()
            ->fetchAll();
        if (count($rows) > 0) {
            $configuration = json_decode($rows[0]['configuration'], true);
            $permissions = $configuration['permissions'] ?? [];
        }
        return $permissions;
    }

    protected function getQueryBuilder(): QueryBuilder
    {
        return GeneralUtility::makeInstance(ConnectionPool::class)
            ->getQueryBuilderForTable(self::TABLE);
    }
}
