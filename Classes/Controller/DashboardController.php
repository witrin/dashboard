<?php
declare(strict_types=1);

namespace FriendsOfTYPO3\Dashboard\Controller;

use FriendsOfTYPO3\Dashboard\Configuration\Widget;
use FriendsOfTYPO3\Dashboard\DashboardConfiguration;
use FriendsOfTYPO3\Dashboard\Dashboards\AbstractDashboard;
use FriendsOfTYPO3\Dashboard\Dashboards\DashboardRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Routing\Exception\RouteNotFoundException as RouteNotFoundExceptionAlias;
use TYPO3\CMS\Backend\Routing\UriBuilder;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Core\Http\HtmlResponse;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\PathUtility;
use TYPO3\CMS\Extbase\Mvc\View\ViewInterface;
use TYPO3\CMS\Fluid\View\StandaloneView;

/**
 * Class DashboardController
 * @codeCoverageIgnore no coverage for controllers yet
 */
class DashboardController extends AbstractController
{
    private const DEFAULT_DASHBOARD_IDENTIFIER = 'dashboard-default';

    /**
     * @var ModuleTemplate
     */
    protected $moduleTemplate;

    /**
     * @var UriBuilder
     */
    protected $uriBuilder;

    /**
     * @var ViewInterface
     */
    protected $view;

    /**
     * @var DashboardConfiguration
     */
    protected $dashboardConfiguration;

    /**
     * @var DashboardRepository
     */
    protected $dashboardRepository;

    /**
     * @var array
     */
    protected $cssFiles = [];

    /**
     * @var array
     */
    protected $jsFiles = [];

    public function __construct(ModuleTemplate $moduleTemplate = null, UriBuilder $uriBuilder = null, DashboardConfiguration $dashboardConfiguration = null, DashboardRepository $dashboardRepository = null)
    {
        $this->moduleTemplate = $moduleTemplate ?? GeneralUtility::makeInstance(ModuleTemplate::class);
        $this->uriBuilder = $uriBuilder ?? GeneralUtility::makeInstance(UriBuilder::class);
        $this->dashboardConfiguration = $dashboardConfiguration ?? GeneralUtility::makeInstance(DashboardConfiguration::class);
        $this->dashboardRepository = $dashboardRepository ?? GeneralUtility::makeInstance(DashboardRepository::class);
    }

    /**
     * Main entry method: Dispatch to other actions - those method names that end with "Action".
     *
     * @param ServerRequestInterface $request the current request
     * @return ResponseInterface the response with the content
     */
    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
        $publicResourcesPath = PathUtility::getAbsoluteWebPath(ExtensionManagementUtility::extPath('dashboard')) . 'Resources/Public/';
        $pageRenderer = $this->moduleTemplate->getPageRenderer();
        $pageRenderer->addRequireJsConfiguration(
            [
                'paths' => [
                    'muuri' => $publicResourcesPath . 'JavaScript/Dist/Muuri',
                ],
            ]
        );

        $pageRenderer->loadRequireJsModule('muuri');
        $pageRenderer->loadRequireJsModule('TYPO3/CMS/Dashboard/Grid');
        $pageRenderer->loadRequireJsModule('TYPO3/CMS/Dashboard/WidgetContentCollector');
        $pageRenderer->loadRequireJsModule('TYPO3/CMS/Dashboard/WidgetSelector');
        $pageRenderer->loadRequireJsModule('TYPO3/CMS/Dashboard/DashboardSelector');
        $pageRenderer->loadRequireJsModule('TYPO3/CMS/Dashboard/WidgetRemover');
        $pageRenderer->addCssFile($publicResourcesPath . 'CSS/dashboard.min.css');

        $action = $request->getQueryParams()['action'] ?? $request->getParsedBody()['action'] ?? 'main';
        $this->initializeView($action);

        $result = $this->{$action . 'Action'}($request);
        if ($result instanceof ResponseInterface) {
            return $result;
        }

        foreach ($this->cssFiles as $cssFile) {
            $pageRenderer->addCssFile($cssFile);
        }

        foreach ($this->jsFiles as $key => $jsFile) {
            $pageRenderer->addRequireJsConfiguration([
                'paths' => [
                    $key => $jsFile
                ]
            ]);
            $pageRenderer->loadRequireJsModule($key);
        }

        $this->moduleTemplate->setContent($this->view->render());
        return new HtmlResponse($this->moduleTemplate->renderContent());
    }

    public function mainAction(): void
    {
        $dashboards = $this->getDashboardsForCurrentUser();
        if (count($dashboards) === 0) {
            $dashboards = [];
            $dashboard = $this->dashboardRepository->createDashboard($this->dashboardConfiguration->getDashboards()[self::DEFAULT_DASHBOARD_IDENTIFIER]);
            $dashboards[$dashboard->getIdentifier()] = $dashboard;
            $this->setCurrentDashboard($dashboard->getIdentifier());
        }
        $currentDashboard = $this->getCurrentDashboard();
        if ($currentDashboard === '' || !isset($dashboards[$currentDashboard])) {
            $currentDashboard = $dashboards[array_key_first($dashboards)]->getIdentifier();
            $this->setCurrentDashboard($currentDashboard);
        }
        $availableWidgets = [];
        foreach ($this->dashboardConfiguration->getWidgets() as $availableWidgetConfiguration) {
            $availableWidgets[$availableWidgetConfiguration->getIdentifier()] = GeneralUtility::makeInstance($availableWidgetConfiguration->getClassname());
        }
        $this->getJavascriptForWidgets($availableWidgets);
        $this->getCssForWidgets($availableWidgets);

        $widgets = [];
        foreach ($dashboards[$currentDashboard]->getConfiguration()['widgets'] as $widgetHash => $widget) {
            $widgets[$widgetHash] = $this->dashboardRepository->createWidgetRepresentation($widget['identifier'], $widget['config']);
        }
        $this->view->assignMultiple([
            'widgets' => $widgets,
            'availableWidgets' => $availableWidgets,
            'availableDashboards' => $dashboards,
            'dashboardConfigurations' => $this->dashboardConfiguration->getDashboards(),
            'currentDashboard' => $currentDashboard,
            'addWidgetUri' => (string)$this->uriBuilder->buildUriFromRoute('dashboard', [
                'widget' => '@widget',
                'action' => 'addWidget'
            ]),
            'addDashboardUri' => (string)$this->uriBuilder->buildUriFromRoute('dashboard', [
                'widget' => '@widget',
                'action' => 'addDashboard'
            ]),
        ]);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function removeWidgetAction(ServerRequestInterface $request): ResponseInterface
    {
        $parameters = $request->getQueryParams();
        $widgetHash = $parameters['widgetHash'];
        $dashboard = $this->dashboardRepository->getDashboardByIdentifier($this->getCurrentDashboard());
        $widgets = [];
        if ($dashboard !== null) {
            $widgets = $dashboard->getConfiguration()['widgets'] ?? [];
        }
        if (array_key_exists($widgetHash, $widgets)) {
            unset($widgets[$widgetHash]);
            $this->dashboardRepository->updateWidgets($dashboard, $widgets);
        }
        $route = $this->uriBuilder->buildUriFromRoute('dashboard', ['action' => 'main']);
        return new RedirectResponse($route);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function addWidgetAction(ServerRequestInterface $request): ResponseInterface
    {
        $parameters = $request->getQueryParams();
        $widgetKey = $parameters['widget'];

        if ($widgetKey) {
            $dashboard = $this->dashboardRepository->getDashboardByIdentifier($this->getCurrentDashboard());
            $widgets = [];
            if ($dashboard !== null) {
                $widgets = $dashboard->getConfiguration()['widgets'] ?? [];
            }
            $hash = sha1($widgetKey . '-' . time());
            // @TODO: The creation of $widgets is not perfect, we should move this into a central place and work with objects
            $widgets[$hash] = ['identifier' => $widgetKey, 'config' => json_decode('[]', false)];
            $this->dashboardRepository->updateWidgets($dashboard, $widgets);
        }

        $route = $this->uriBuilder->buildUriFromRoute('dashboard', ['action' => 'main']);
        return new RedirectResponse($route);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function addDashboardAction(ServerRequestInterface $request): ResponseInterface
    {
        $parameters = $request->getQueryParams();
        $dashboardIdentifier = $parameters['dashboard'] ?? '';

        $route = $this->uriBuilder->buildUriFromRoute('dashboard', ['action' => 'main']);
        if ($dashboardIdentifier !== '') {
            $dashboard = $this->dashboardRepository->createDashboard($this->dashboardConfiguration->getDashboards()[$dashboardIdentifier]);
            $route = $this->uriBuilder->buildUriFromRoute('dashboard', ['action' => 'setActiveDashboard', 'currentDashboard' => $dashboard->getIdentifier()]);
        }

        return new RedirectResponse($route);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     * @throws RouteNotFoundExceptionAlias
     */
    public function setActiveDashboardAction(ServerRequestInterface $request): ResponseInterface
    {
        $this->setCurrentDashboard($request->getQueryParams()['currentDashboard']);
        $route = $this->uriBuilder->buildUriFromRoute('dashboard', ['action' => 'main']);
        return new RedirectResponse($route);
    }

    /**
     * Sets up the Fluid View.
     *
     * @param string $templateName
     */
    protected function initializeView(string $templateName): void
    {
        $this->view = GeneralUtility::makeInstance(StandaloneView::class);
        $this->view->setTemplate($templateName);
        $this->view->setTemplateRootPaths(['EXT:dashboard/Resources/Private/Templates/Dashboard']);
        $this->view->setPartialRootPaths(['EXT:dashboard/Resources/Private/Partials']);
        $this->view->setLayoutRootPaths(['EXT:dashboard/Resources/Private/Layouts']);

        $this->moduleTemplate->getDocHeaderComponent()->disable();
    }

    /**
     * @return AbstractDashboard[]
     */
    protected function getDashboardsForCurrentUser(): array
    {
        // @TODO: filter here for access restrictions later
        $dashboards = [];
        foreach ($this->dashboardRepository->getAllDashboards() as $dashboard) {
            $dashboards[$dashboard->getIdentifier()] = $dashboard;
        }
        return $dashboards;
    }

    /**
     * @param Widget[] $widgets
     * @throws \Exception
     */
    protected function getJavascriptForWidgets(array $widgets): void
    {
        foreach ($widgets as $widget) {
            foreach ($widget->getJsFiles() as $key => $jsFile) {
                if (!in_array($jsFile, $this->jsFiles, true)) {
                    $this->jsFiles[$key] = $jsFile;
                }
            }
        }
    }

    /**
     * @param Widget[] $widgets
     * @throws \Exception
     */
    protected function getCssForWidgets(array $widgets): void
    {
        foreach ($widgets as $widget) {
            foreach ($widget->getCssFiles() as $cssFile) {
                if (!in_array($cssFile, $this->cssFiles, true)) {
                    $this->cssFiles[] = $cssFile;
                }
            }
        }
    }
}
