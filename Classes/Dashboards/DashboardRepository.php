<?php
declare(strict_types=1);

namespace FriendsOfTYPO3\Dashboard\Dashboards;

use FriendsOfTYPO3\Dashboard\Configuration\Dashboard;
use FriendsOfTYPO3\Dashboard\Configuration\Widget;
use FriendsOfTYPO3\Dashboard\DashboardConfiguration;
use FriendsOfTYPO3\Dashboard\Widgets\WidgetInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class DashboardRepository
{
    private const TABLE = 'sys_dashboards';

    /** @var DashboardConfiguration */
    protected $dashboardConfiguration;

    public function __construct(DashboardConfiguration $dashboardConfiguration = null)
    {
        $this->dashboardConfiguration = $dashboardConfiguration ?? GeneralUtility::makeInstance(DashboardConfiguration::class);
    }

    /**
     * @return AbstractDashboard[]
     */
    public function getAllDashboards(): array
    {
        $rows = $this->getQueryBuilder()
            ->select('*')
            ->from(self::TABLE)
            ->execute()
            ->fetchAll();
        $results = [];
        foreach ($rows as $row) {
            $results[] = $this->createFromRow($row);
        }
        return $results;
    }

    /**
     * @param string $identifier
     * @return AbstractDashboard
     */
    public function getDashboardByIdentifier(string $identifier): ?AbstractDashboard
    {
        $queryBuilder = $this->getQueryBuilder();
        $row = $queryBuilder
            ->select('*')
            ->from(self::TABLE)
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)))
            ->execute()
            ->fetchAll();
        if (count($row)) {
            return $this->createFromRow($row[0]);
        }
        return null;
    }

    public function createDashboard(Dashboard $dashboardConfiguration): AbstractDashboard
    {
        $configuration = ['widgets' => []];
        foreach ($dashboardConfiguration->getWidgets() as $widget) {
            $hash = sha1($widget . '-' . time());
            $configuration['widgets'][$hash] = ['identifier' => $widget, 'config' => json_decode('[]', false)];
        }
        $identifier = sha1($dashboardConfiguration->getIdentifier() . '-' . time());
        $this->getQueryBuilder()
            ->insert(self::TABLE)
            ->values([
                'identifier' => $identifier,
                'label' => $dashboardConfiguration->getLabel(),
                'configuration' => json_encode($configuration)
            ])
            ->execute();
        return $this->getDashboardByIdentifier($identifier);
    }

    /**
     * @param $widgetIdentifier
     * @param array $config
     * @return array
     * @throws \Exception
     */
    public function createWidgetRepresentation($widgetIdentifier, $config = []): array
    {
        // @TODO: This method and the whole Widget system should be adjusted
        // @TODO: Maybe add WidgetFactory which creates Widget instances from configuration
        // @TODO: The AbstractWidget should implement JsonSerializable to provide an easy representation for the view.
        $widgetConfiguration = $this->dashboardConfiguration->getWidgets()[$widgetIdentifier];
        if ($widgetConfiguration instanceof Widget) {
            $widgetObject = GeneralUtility::makeInstance($widgetConfiguration->getClassname());
            if ($widgetObject instanceof WidgetInterface) {
                return [
                    'identifier' => $widgetIdentifier,
                    'height' => $widgetObject->getHeight(),
                    'width' => $widgetObject->getWidth(),
                    'title' => $widgetObject->getTitle(),
                    'additionalClasses' => $widgetObject->getAdditionalClasses(),
                    'config' => $config
                ];
            }
        }

        return [];
    }

    /**
     * @param AbstractDashboard $dashboard
     * @param string[] $widgets
     */
    public function updateWidgets(AbstractDashboard $dashboard, array $widgets): void
    {
        $configuration = $dashboard->getConfiguration();
        $configuration['widgets'] = $widgets;
        $queryBuilder = $this->getQueryBuilder();
        $queryBuilder
            ->update(self::TABLE)
            ->set('configuration', json_encode($configuration))
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($dashboard->getIdentifier())))
            ->execute();
    }

    protected function createFromRow(array $row): AbstractDashboard
    {
        return GeneralUtility::makeInstance(DefaultDashboard::class, $row['identifier'], $row['label'], json_decode($row['configuration'], true));
    }

    protected function getQueryBuilder(): QueryBuilder
    {
        return GeneralUtility::makeInstance(ConnectionPool::class)
            ->getQueryBuilderForTable(self::TABLE);
    }
}
