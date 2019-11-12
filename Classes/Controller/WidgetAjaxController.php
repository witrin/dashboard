<?php
declare(strict_types=1);

namespace FriendsOfTYPO3\Dashboard\Controller;

use FriendsOfTYPO3\Dashboard\Configuration\Widget;
use FriendsOfTYPO3\Dashboard\DashboardConfiguration;
use FriendsOfTYPO3\Dashboard\Dashboards\DashboardRepository;
use FriendsOfTYPO3\Dashboard\Security\AccessControl\Attribute\DashboardAttribute;
use FriendsOfTYPO3\Dashboard\Security\AccessControl\Attribute\RemoveWidgetAttribute;
use FriendsOfTYPO3\Dashboard\Security\AccessControl\Attribute\WidgetAttribute;
use FriendsOfTYPO3\Dashboard\Widgets\WidgetInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Http\JsonResponse;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Security\AccessControl\Policy\PolicyDecisionPoint;

/**
 * Class WidgetAjaxController
 * @codeCoverageIgnore no coverage for controllers yet
 */
class WidgetAjaxController extends AbstractController
{
    /**
     * @var DashboardConfiguration
     */
    protected $dashboardConfiguration;

    /**
     * @var DashboardRepository
     */
    protected $dashboardRepository;

    public function __construct(DashboardConfiguration $dashboardConfiguration = null, DashboardRepository $dashboardRepository = null, PolicyDecisionPoint $policyDecisionPoint = null)
    {
        $this->dashboardConfiguration = $dashboardConfiguration ?? GeneralUtility::makeInstance(DashboardConfiguration::class);
        $this->dashboardRepository = $dashboardRepository ?? GeneralUtility::makeInstance(DashboardRepository::class);
        $this->policyDecisionPoint = $policyDecisionPoint ?? GeneralUtility::makeInstance(PolicyDecisionPoint::class);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     * @throws \Exception
     */
    public function getContent(ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();
        // @TODO: $queryParams['widget'] contains the type and not the instance identifier/hash.
        // @TODO: The content must be fetch by instance identifier/hash to make access checks possible
        // @TODO: and allow multiple widgets of the same type with different configurations.
        $widgetConfiguration = $this->dashboardConfiguration->getWidgets()[$queryParams['widget']];

        $data = [];

        // @TODO: Add check with $this->hasAccess()
        if ($widgetConfiguration instanceof Widget) {
            $widgetObject = GeneralUtility::makeInstance($widgetConfiguration->getClassname());
            if ($widgetObject instanceof WidgetInterface) {
                $data = [
                    'widget' => $queryParams['widget'],
                    'content' => $widgetObject->renderWidgetContent(),
                    'eventdata' => $widgetObject->getEventData()
                ];
            }
        }
        return new JsonResponse($data);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function savePositions(ServerRequestInterface $request): ResponseInterface
    {
        // @TODO: What about a permission check? E.g. dashboard:sorting ?
        $body = $request->getParsedBody();
        $widgets = [];
        // @TODO: The creation of $widgets is not perfect, we should move this into a central place and work with objects
        foreach ($body['widgets'] as $widget) {
            $widgets[$widget[2]] = ['identifier' => $widget[0], 'config' => json_decode($widget[1], false)];
        }
        $dashboard = $this->dashboardRepository->getDashboardByIdentifier($this->getCurrentDashboard());
        if ($dashboard !== null) {
            $this->dashboardRepository->updateWidgets($dashboard, $widgets);
        }
        return new JsonResponse(['status' => 'saved']);
    }
}
