<?php
declare(strict_types=1);

namespace FriendsOfTYPO3\Dashboard\Widgets;

use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\PathUtility;
use TYPO3\CMS\Extbase\Utility\DebuggerUtility;

abstract class AbstractRssWidget extends AbstractListWidget
{
    protected $rssFile = '';

    protected $limit = 3;

    /**
     * @var string
     */
    protected $templateName = 'RssWidget';

    public function __construct()
    {
        AbstractListWidget::__construct();
        $this->width = 2;
        $this->height = 3;

        $publicResourcesPath = PathUtility::getAbsoluteWebPath(ExtensionManagementUtility::extPath('dashboard')) . 'Resources/Public/';
        $this->cssFiles[] = $publicResourcesPath . 'CSS/rssWidget.css';
    }

    public function prepareData(): void
    {
        /** @var \SimpleXMLElement $rssFeed */
        $rssFeed = simplexml_load_file($this->rssFile);

        $itemCount = 0;
        foreach ($rssFeed->channel->item as $item) {
            if ($itemCount < $this->limit) {
                $this->items[] = [
                    'title' => $item->title,
                    'link' => $item->link,
                    'pubDate' => $item->pubDate,
                    'description' => $item->description,
                ];
            } else {
                continue;
            }

            $itemCount++;
        }
    }
}
