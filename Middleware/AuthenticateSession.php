<?php

namespace Satupersen\Session\Middleware;

use Closure;
use Satupersen\Auth\AuthenticationException;
use Satupersen\Contracts\Auth\Factory as AuthFactory;

class AuthenticateSession
{
    /**
     * The authentication factory implementation.
     *
     * @var \Satupersen\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \Satupersen\Contracts\Auth\Factory  $auth
     * @return void
     */
    public function __construct(AuthFactory $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Satupersen\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (! $request->hasSession() || ! $request->user()) {
            return $next($request);
        }

        if ($this->auth->viaRemember()) {
            $passwordHash = explode('|', $request->cookies->get($this->auth->getRecallerName()))[2];

            if ($passwordHash != $request->user()->getAuthPassword()) {
                $this->logout($request);
            }
        }

        if (! $request->session()->has('password_hash')) {
            $this->storePasswordHashInSession($request);
        }

        if ($request->session()->get('password_hash') !== $request->user()->getAuthPassword()) {
            $this->logout($request);
        }

        return tap($next($request), function () use ($request) {
            $this->storePasswordHashInSession($request);
        });
    }

    /**
     * Store the user's current password hash in the session.
     *
     * @param  \Satupersen\Http\Request  $request
     * @return void
     */
    protected function storePasswordHashInSession($request)
    {
        if (! $request->user()) {
            return;
        }

        $request->session()->put([
            'password_hash' => $request->user()->getAuthPassword(),
        ]);
    }

    /**
     * Log the user out of the application.
     *
     * @param  \Satupersen\Http\Request  $request
     * @return void
     *
     * @throws \Satupersen\Auth\AuthenticationException
     */
    protected function logout($request)
    {
        $this->auth->logoutCurrentDevice();

        $request->session()->flush();

        throw new AuthenticationException;
    }
}
