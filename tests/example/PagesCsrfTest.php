<?php

namespace web_eid\web_eid_authtoken_validation_php\example;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../example/src/Template.php';
require_once __DIR__ . '/../../example/src/Pages.php';

final class PagesCsrfTest extends TestCase
{
    public function testOpeningAnotherPageKeepsTheFirstPagesCsrfTokenValid(): void
    {
        $previousSession = $_SESSION ?? null;
        $_SESSION = [];
        try {
            $firstToken = $this->renderPageToken('login');
            self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $firstToken);
            self::assertSame($firstToken, $_SESSION['csrf-token']);

            // Another tab or the mobile callback must not invalidate the first page.
            self::assertSame($firstToken, $this->renderPageToken('login'));
            self::assertSame($firstToken, $this->renderPageToken('mobileLoginView'));
            self::assertSame($firstToken, $_SESSION['csrf-token']);
        } finally {
            if ($previousSession === null) {
                unset($_SESSION);
            } else {
                $_SESSION = $previousSession;
            }
        }
    }

    private function renderPageToken(string $action): string
    {
        ob_start();
        try {
            $page = new \Pages();
            $page->$action();
            unset($page); // Pages renders the outer template in its destructor.
            $html = ob_get_contents();
        } finally {
            ob_end_clean();
        }
        self::assertSame(1, preg_match('/<meta id="csrftoken" name="csrftoken" content="([^"]*)"/', $html, $matches));
        return $matches[1];
    }
}
