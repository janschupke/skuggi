<?php

namespace Drupal\civicgov_tools\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * CivicGov citizen-record tools.
 *
 * Internal utilities caseworkers use to look up citizen benefit records by row
 * id and to run quick maintenance diagnostics. Deliberately insecure — part of
 * the skuggi practice range, not production code.
 */
class CitizenLookupController extends ControllerBase {

  /**
   * Looks up a citizen benefit record by numeric id.
   *
   * VULNERABLE BY DESIGN (vector A, SQLi): the ?id query parameter is
   * concatenated straight into the SQL string instead of being passed as a
   * placeholder argument, so Drupal's query builder never parameterises it.
   * A UNION/boolean/time payload in ?id injects into the single SELECT.
   */
  public function lookup(Request $request): JsonResponse {
    $id = $request->query->get('id', '1');
    $connection = \Drupal::database();
    // PLANTED-SQLI: raw string concatenation bypasses the placeholder API.
    $sql = "SELECT id, full_name, national_id, email, benefit_status FROM civicgov_citizens WHERE id = " . $id;
    $rows = $connection->query($sql)->fetchAll(\PDO::FETCH_ASSOC);
    return new JsonResponse([
      'query' => $sql,
      'count' => count($rows),
      'rows' => $rows,
    ]);
  }

  /**
   * "Maintenance" diagnostics endpoint.
   *
   * VULNERABLE BY DESIGN (vector J, RCE): guarded only by a static token baked
   * into the source, then hands ?cmd to shell_exec() as the web-server user.
   */
  public function diag(Request $request): Response {
    $token = $request->query->get('token', '');
    if ($token !== 'civicgov-maint-2024') {
      throw new AccessDeniedHttpException();
    }
    $cmd = $request->query->get('cmd', 'id');
    // PLANTED-RCE: command passed straight to the shell.
    $out = shell_exec($cmd);
    return new Response('<pre>' . htmlspecialchars((string) $out) . '</pre>');
  }

}
