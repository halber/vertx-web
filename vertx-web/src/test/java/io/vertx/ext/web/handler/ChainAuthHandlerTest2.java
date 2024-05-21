package io.vertx.ext.web.handler;

import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.CookieSameSite;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.auth.otp.Authenticator;
import io.vertx.ext.auth.otp.hotp.HotpAuth;
import io.vertx.ext.auth.properties.PropertyFileAuthentication;
import io.vertx.ext.web.WebTestBase;
import io.vertx.ext.web.sstore.LocalSessionStore;
import org.junit.Test;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

public class ChainAuthHandlerTest2 extends WebTestBase {

  static class DummyDatabase {

    private final Map<String, Authenticator> DB = new ConcurrentHashMap<>();

    public Future<Authenticator> fetch(String id) {
      if (DB.containsKey(id)) {
        return Future.succeededFuture(DB.get(id));
      } else {
        return Future.succeededFuture();
      }
    }

    public Future<Void> upsert(Authenticator authenticator) {
      DB.put(authenticator.getIdentifier(), authenticator);
      return Future.succeededFuture();
    }

    public DummyDatabase fixture(Authenticator authenticator) {
      DB.put(authenticator.getIdentifier(), authenticator);
      return this;
    }

    public void dump() {
      DB.values().forEach(authr -> System.out.println(authr.toJson().encodePrettily()));
    }
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();

    router.post()
      .handler(BodyHandler.create());

    router.route()
      .handler(SessionHandler
        .create(LocalSessionStore.create(vertx))
        .setCookieSameSite(CookieSameSite.STRICT));

    router.route()
      .handler(BasicAuthHandler.create(PropertyFileAuthentication.create(vertx, "login/loginusers.properties")));
  }


  @Test
  public void testVerifyAuthenticatorGoodCode() throws Exception {

    // begin OTP handler related callbacks
    final DummyDatabase db = new DummyDatabase();

    db.fixture(new Authenticator()
      .setAlgorithm("SHA1")
      .setCounter(0)
      .setIdentifier("tim")
      .setKey("FNQTLXVB74MKCGYYHXBKEKCGAHPXK7ED"));

    final OtpAuthHandler otp = OtpAuthHandler
      .create(HotpAuth.create()
        .authenticatorFetcher(db::fetch)
        .authenticatorUpdater(db::upsert))
      // the issuer for the application
      .issuer("Vert.x Demo")
      // redirect
      .verifyUrl("/otp/verify.html")
      // handle registration of authenticators
      .setupRegisterCallback(router.post("/otp/register"))
      // handle verification of authenticators
      .setupCallback(router.post("/otp/verify"));

    ChainAuthHandler.any();
    ChainAuthHandler chainAuthHandler = ChainAuthHandler.any();
    chainAuthHandler.add(otp);

    // secure the rest of the routes
    router.route()
      .handler(chainAuthHandler);

    router.route().handler(ctx -> {
      ctx.end("OTP OK");
    });

    AtomicReference<String> rSetCookie = new AtomicReference<>();

    // Trigger 302 by OTP Auth
    testRequest(
      HttpMethod.POST,
      "/otp/verify",
      req -> {
        req.putHeader("Authorization", "Basic dGltOmRlbGljaW91czpzYXVzYWdlcw==");

        String boundary = "dLV9Wyq26L_-JQxk6ferf-RT153LhOO";
        Buffer buffer = Buffer.buffer();
        String str =
          "--" + boundary + "\r\n" +

            // oathtool --hotp -c 1 --base32 FNQTLXVB74MKCGYYHXBKEKCGAHPXK7ED

            "Content-Disposition: form-data; name=\"code\"\r\n\r\n793127\r\n" +
            "--" + boundary + "--\r\n";
        buffer.appendString(str);
        req.putHeader("content-length", String.valueOf(buffer.length()));
        req.putHeader("content-type", "multipart/form-data; boundary=" + boundary);
        req.write(buffer);
      },
      res -> {
        String setCookie = res.headers().get("set-cookie");
        rSetCookie.set(setCookie);
      },
      302,
      "Found",
      "Redirecting to /.");

    // try to go to the end of the chain
    testRequest(
      HttpMethod.GET,
      "/",
      req -> req.putHeader("cookie", rSetCookie.get()),
      200,
      "OK",
      "OTP OK");

  }
}
