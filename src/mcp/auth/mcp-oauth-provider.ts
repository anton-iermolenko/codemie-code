/**
 * MCP OAuth Client Provider
 *
 * Implements the OAuthClientProvider interface from the MCP SDK for browser-based
 * OAuth authorization code flow. All state is memory-only (no persistent storage).
 *
 * Flow: 401 → resource metadata → auth server metadata → dynamic client registration
 * (client_name from MCP_CLIENT_NAME env var, default "CodeMie CLI") → browser authorization → callback → token exchange.
 */

import { execFile } from 'child_process';
import { logger } from '../../utils/logger.js';
import { getMcpClientName } from '../constants.js';
import { acquireAuthLock } from './auth-lock.js';
import { startCallbackServer, type CallbackResult } from './callback-server.js';

import type {
  OAuthClientProvider,
  OAuthClientMetadata,
  OAuthClientInformationMixed,
  OAuthTokens,
} from '@modelcontextprotocol/client';

/**
 * In-memory OAuth provider for MCP authorization code flow.
 * Tokens and client info are stored in memory only — re-auth required each session.
 */
export class McpOAuthProvider implements OAuthClientProvider {
  private _redirectUrl: string | undefined;
  private _clientInfo: OAuthClientInformationMixed | undefined;
  private _tokens: OAuthTokens | undefined;
  private _expiresAt: number | undefined;
  private _codeVerifier: string | undefined;
  // Reused by later logins so the redirect URI registered with the client stays valid
  private _callbackPort: number | undefined;

  // Callback server state (active during authorization)
  private callbackWait: Promise<CallbackResult> | undefined;
  private callbackClose: (() => void) | undefined;
  // Held from opening the browser until the login settles, so proxies log in one at a time
  private releaseAuthLock: (() => void) | undefined;

  get redirectUrl(): string | undefined {
    return this._redirectUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: getMcpClientName(),
      redirect_uris: this._redirectUrl ? [this._redirectUrl] : [],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    };
  }

  /**
   * Pre-start the callback server so that clientMetadata.redirect_uris is
   * populated before the SDK calls registerClient(). Must be called before
   * connecting the HTTP transport.
   */
  async ensureCallbackServer(): Promise<void> {
    if (this.callbackWait) return;
    const { redirectUrl, waitForCallback, close } = await startCallbackServer({
      preferredPort: this._callbackPort,
    });
    this._redirectUrl = redirectUrl;
    this._callbackPort = Number(new URL(redirectUrl).port);
    this.callbackWait = waitForCallback;
    this.callbackClose = close;
    // Nobody awaits this until a login starts. If none is ever needed (a server without OAuth),
    // the callback timeout would surface as an unhandled rejection. Awaiting it later still throws.
    waitForCallback.catch(() => {});
    logger.debug(`[mcp-proxy] Callback server pre-started: ${redirectUrl}`);
  }

  clientInformation(): OAuthClientInformationMixed | undefined {
    return this._clientInfo;
  }

  saveClientInformation(info: OAuthClientInformationMixed): void {
    this._clientInfo = info;
    logger.debug('[mcp-proxy] Saved client information (memory-only)');
  }

  tokens(): OAuthTokens | undefined {
    return this._tokens;
  }

  saveTokens(tokens: OAuthTokens): void {
    this._tokens = tokens;
    this._expiresAt = typeof tokens.expires_in === 'number' ? Date.now() + tokens.expires_in * 1000 : undefined;
    logger.debug('[mcp-proxy] Saved OAuth tokens (memory-only)');
  }

  /** True when the current access token is known to be expired (or about to be). */
  tokenNeedsRenewal(skewMs = 60_000): boolean {
    return this._tokens !== undefined && this._expiresAt !== undefined && this._expiresAt - skewMs <= Date.now();
  }

  /**
   * Prepare a login that happens after the initial connect: the callback server of the previous
   * login is gone, and the authorization URL is built from `redirectUrl` before the browser is
   * opened, so a fresh server must exist first. If it could not reuse the old port, the redirect
   * URI registered with the client no longer matches and the client must be registered again.
   */
  async prepareReauthentication(): Promise<void> {
    // A server pre-started at connect time may be unused (no login was needed then) and may have
    // timed out by now. Replace it (the port is freed on close, so the new one can reuse it).
    this.callbackClose?.();
    this.callbackWait = undefined;
    this.callbackClose = undefined;
    await this.ensureCallbackServer();
    const registered = this._clientInfo && 'redirect_uris' in this._clientInfo
      ? this._clientInfo.redirect_uris
      : undefined;
    if (registered && this._redirectUrl && !registered.map(String).includes(this._redirectUrl)) {
      this.invalidateCredentials('client');
    }
  }

  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Start ephemeral callback server if not already running
    await this.ensureCallbackServer();

    // Concurrent logins from sibling proxies clobber each other's gateway CSRF/session state
    // in the browser, so wait for any other pending login to finish first.
    if (!this.releaseAuthLock) {
      this.releaseAuthLock = await acquireAuthLock();
    }

    const url = authorizationUrl.toString();
    logger.debug(`[mcp-proxy] Opening browser for authorization`);
    console.error('[mcp-proxy] Opening browser for MCP server authorization...');

    openBrowser(url);
  }

  saveCodeVerifier(codeVerifier: string): void {
    this._codeVerifier = codeVerifier;
  }

  codeVerifier(): string {
    return this._codeVerifier || '';
  }

  invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier' | 'discovery'): void {
    if (scope === 'all' || scope === 'tokens') {
      this._tokens = undefined;
      this._expiresAt = undefined;
    }
    if (scope === 'all' || scope === 'client') {
      this._clientInfo = undefined;
    }
    if (scope === 'all' || scope === 'verifier') {
      this._codeVerifier = undefined;
    }
    logger.debug(`[mcp-proxy] Invalidated credentials: ${scope}`);
  }

  /**
   * Wait for the OAuth callback after browser redirect.
   * Returns the authorization code from the callback.
   * This is called externally by the bridge after auth() returns 'REDIRECT'.
   */
  async waitForAuthorizationCode(): Promise<string> {
    if (!this.callbackWait) {
      throw new Error('No active authorization flow — callback server not started');
    }

    try {
      const result = await this.callbackWait;
      logger.debug('[mcp-proxy] Received authorization callback');
      return result.code;
    } finally {
      this.callbackWait = undefined;
      this.callbackClose = undefined;
      this.releaseLock();
    }
  }

  private releaseLock(): void {
    this.releaseAuthLock?.();
    this.releaseAuthLock = undefined;
  }

  /**
   * Clean up the callback server if still running (e.g., on shutdown).
   */
  dispose(): void {
    this.callbackClose?.();
    this.callbackWait = undefined;
    this.callbackClose = undefined;
    this.releaseLock();
  }
}

/**
 * Open a URL in the system default browser.
 * Cross-platform: macOS (open), Windows (start), Linux (xdg-open).
 */
function openBrowser(url: string): void {
  const platform = process.platform;
  let command: string;
  let args: string[];

  if (platform === 'darwin') {
    command = 'open';
    args = [url];
  } else if (platform === 'win32') {
    // Use PowerShell Start-Process to avoid CMD metacharacter parsing:
    // `cmd /c start "" url` splits on `&`, truncating auth URLs with query params.
    // PowerShell passes the URL directly to the OS shell handler, preserving all chars.
    const escapedUrl = url.replace(/'/g, "''"); // PowerShell single-quote escaping
    command = 'powershell';
    args = ['-NoProfile', '-Command', `Start-Process '${escapedUrl}'`];
  } else {
    command = 'xdg-open';
    args = [url];
  }

  execFile(command, args, (error) => {
    if (error) {
      // Don't fail — user can manually copy the URL from stderr
      console.error(`[mcp-proxy] Could not open browser automatically. Please open this URL:\n${url}`);
    }
  });
}
