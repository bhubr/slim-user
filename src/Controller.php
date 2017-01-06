<?php
namespace bhubr\SlimUser;

use Slim\Csrf\Guard;
use Slim\Views\Twig;
use Psr\Log\LoggerInterface;
use Illuminate\Database\Query\Builder;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use App\Model\User;

class Controller
{
    private $view;
    private $logger;
    protected $table;
    private $csrf;
    private $csrfNameKey;
    private $csrfValueKey;

    public function __construct(
        Guard $csrf,
        Twig $view,
        LoggerInterface $logger,
        Builder $table
    ) {
        $this->csrf = $csrf;
        $this->view = $view;
        $this->logger = $logger;
        $this->table = $table;

        $this->csrfNameKey = $this->csrf->getTokenNameKey();
        $this->csrfValueKey = $this->csrf->getTokenValueKey();
    }
}