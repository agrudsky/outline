import Router from "koa-router";
import passport from "passport";
import { Strategy as SAMLStrategy } from "passport-saml";
import validator from "validator";
import accountProvisioner from "@server/commands/accountProvisioner";
import env from "@server/env";
import { SAMLAssertionError } from "@server/errors";
import auth from "@server/middlewares/authentication";
import passportMiddleware from "@server/middlewares/passport";
import { StateStore, getSAMLProviderDisplayName } from "@server/utils/passport";

const router = new Router();
const providerName = "saml";
const SAML_CERT = process.env.SAML_CERT;
const SAML_SSO_ENDPOINT = process.env.SAML_SSO_ENDPOINT;

export const config = {
  name: getSAMLProviderDisplayName(SAML_SSO_ENDPOINT),
  enabled: !!SAML_SSO_ENDPOINT,
};

if (SAML_SSO_ENDPOINT) {
  passport.use(
    new SAMLStrategy(
      {
        callbackUrl: `${env.URL}/auth/saml.callback`,
        entryPoint: SAML_SSO_ENDPOINT,
        issuer: "https://app.getoutline.com",
        passReqToCallback: true,
        cert: SAML_CERT,
        name: providerName,
        // @ts-expect-error custom state store
        store: new StateStore(),
      },
      async function (req, profile, done: any) {
        try {
          if (!profile?.fName) {
            throw SAMLAssertionError(
              "fName field must be included as a parameter in SAML assertion"
            );
          }
          if (!profile.sName && !profile.sn) {
            throw SAMLAssertionError(
              "sName field must be included as a parameter in SAML assertion"
            );
          }
          if (!profile.email) {
            throw SAMLAssertionError(
              "email field must be included as a parameter in SAML assertion"
            );
          }
          if (!validator.isEmail(profile.email)) {
            throw SAMLAssertionError(
              `email field in SAML assertion must be a valid email, ${profile.email} provided`
            );
          }
          if (!profile.issuer) {
            throw SAMLAssertionError(
              "issuer field must be included as a parameter in SAML assertion"
            );
          }
          if (!profile.nameID) {
            throw SAMLAssertionError(
              "nameID field must be included as a parameter in SAML assertion"
            );
          }

          const result = await accountProvisioner({
            ip: req.ip,
            team: {
              name: "Wiki",
              subdomain: "wiki",
            },
            user: {
              name: `${profile.fName} ${profile.sName || profile.sn}`,
              email: profile.email.toLowerCase(),
            },
            authenticationProvider: {
              name: providerName,
              providerId: profile.issuer,
            },
            authentication: {
              providerId: profile.nameID,
              scopes: [],
            },
          });
          return done(null, result.user, result);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  router.get("saml", passport.authenticate(providerName));

  router.post(
    "saml.callback",
    auth({ optional: true }),
    passportMiddleware(providerName)
  );
}

export default router;
