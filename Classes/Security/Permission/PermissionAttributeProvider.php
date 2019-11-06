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

use FriendsOfTYPO3\Dashboard\Security\Attribute\DashboardAttribute;
use FriendsOfTYPO3\Dashboard\Security\Attribute\WidgetAttribute;
use TYPO3\CMS\Backend\Security\Attribute\GroupAttribute;
use TYPO3\CMS\Backend\Security\Attribute\PermissionAttribute;
use TYPO3\CMS\Backend\Security\Attribute\UserAttribute;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Exception\InvalidArgumentException;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Security\Attribute\PrincipalAttribute;
use TYPO3\CMS\Security\Event\AttributeRetrivalEvent;

/**
 * @internal
 */
class PermissionAttributeProvider
{
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
        /** @noinspection PhpUnhandledExceptionInspection */
        $userAspect = $event->getContext()->getAspect('backend.user');
        /** @noinspection PhpUnhandledExceptionInspection */
        if (!$userAspect->get('isLoggedIn')) {
            return;
        }
        $attribute = $event->getAttribute();

        if (!$attribute instanceof WidgetAttribute && !$attribute instanceof DashboardAttribute) {
            return;
        }

        // @TODO: Cache disabled for now, because only the first hit wins,
        // @TODO: e.g. first WidgetAttribute or first DashboardAttribute
//        $cacheIdentifier = sha1(static::class . '_user_permissions' . $userAspect->get('id'));
//        if (($entries = $this->cache->get($cacheIdentifier)) === false) {
            $entries = [];
            // @TODO: get existing principals from event (not possible yet)
            if ($attribute instanceof WidgetAttribute) {
                foreach ($this->getPermissionsForWidgetAttribute($attribute) as $principalIdentifier => $permissions) {
                    foreach ($permissions as $action => $state) {
                        $entries[] = $this->createPermissionAttribute($principalIdentifier, $attribute->identifier, $action, $state);
                    }
                }
            }
            if ($attribute instanceof DashboardAttribute) {
                foreach ($this->getPermissionsForDashboardAttribute($attribute) as $principalIdentifier => $permissions) {
                    foreach ($permissions as $action => $state) {
                        $entries[] = $this->createPermissionAttribute($principalIdentifier, $attribute->identifier, $action, $state);
                    }
                }
            }
//            $this->cache->set($cacheIdentifier, $entries);
//        }

        $attribute->permissions = array_merge($attribute->permissions, $entries);;
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

    protected function resolvePrincipalAttribute(string $resourceIdentifier): PrincipalAttribute
    {
        [$resourceType, $resourceId] = GeneralUtility::trimExplode(':', $resourceIdentifier);
        $principalAttribute = null;
        if ($resourceType === 'be_user') {
            $principalAttribute = new UserAttribute((int)$resourceId, 'be_user');
        }
        if ($resourceType === 'be_group') {
            $principalAttribute = new GroupAttribute((int)$resourceId, 'be_group');
        }
        if ($principalAttribute === null) {
            throw new InvalidArgumentException('invalid resource type: ' . $resourceType);
        }
        return $principalAttribute;
    }

    /**
     * Example result:
     * [
     *      'be_user:123' => [
     *          'dashboard:view' => 'permit',
     *          'dashboard:edit' => 'deny',
     *      ]
     * ]
     * @param WidgetAttribute $attribute
     * @return array
     */
    protected function getPermissionsForWidgetAttribute(WidgetAttribute $attribute): array
    {
        $permissions = [];
        $hash = str_replace('dashboard:widget:', '', $attribute->identifier);

        $rows = $this->getQueryBuilder()
            ->select('configuration')
            ->from(self::TABLE)
            ->execute()
            ->fetchAll();
        foreach ($rows as $row) {
            $configuration = json_decode($row['configuration'], true);
            foreach ($configuration['widgets'] as $widgetHash => $widgetConfiguration) {
                if ($widgetHash === $hash) {
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
     * @param DashboardAttribute $attribute
     * @return array
     */
    protected function getPermissionsForDashboardAttribute(DashboardAttribute $attribute): array
    {
        $permissions = [];

        $hash = str_replace('dashboard:dashboard:', '', $attribute->identifier);
        $queryBuilder = $this->getQueryBuilder();
        $rows = $queryBuilder
            ->select('configuration')
            ->from(self::TABLE)
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($hash)))
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
