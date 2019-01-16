using System;
using System.Collections.Generic;
using System.IdentityModel.Policy;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;

namespace RB.GatewayTester
{
    internal class TokenMaker
    {
        private const string USERNAME = "urn:rb/2013/01/claims/federated-username";
        private const string PERSONID = "urn:rb/2013/01/claims/federated-personid";
        private const string FULLNAME = "urn:rb/2013/01/claims/federated-fullname";
        private const string ROLE = "urn:rb/2013/01/claims/federated-role";

        private string _appliesTo;
        private string _issuer;

        /// <summary>
        /// Smiður.
        /// </summary>
        /// <param name="appliesTo">Identifier fyrir þann sem á að taka við tokeninu. Í samkiptum við RB þá er þetta Identifier sem RB lætur Banka X hafa.</param>
        /// <param name="issuer">Identifier fyrir þann sem gefur út tokenið. Í samskiptum við RB þá þarf Banki X að láta RB fá þennan identifier (skráður í Federation provider).</param>
        public TokenMaker(string appliesTo, string issuer)
        {
            _appliesTo = appliesTo;
            _issuer = issuer;
        }


        /// <summary>
        /// Býr til SAML token sem inniheldur claim.
        /// </summary>
        /// <param name="userName">Notandanafn sem fer í claim.</param>
        /// <param name="personId">Kennitala sem fer í claim.</param>
        /// <param name="fullName">Nafn notanda sem fer í claim.</param>
        /// <param name="roles">Listi af hlutverkum sem fara í claim.</param>
        /// <param name="encryptingCertSubject">Subject fyrir skilríki sem er notað til að dulrita token (Skilríkið þarf að vera í My-LocalMachine).</param>
        /// <param name="signingCertSubject">Subject fyrir skilríki sem er notað til að undirrita token (Skilríkið þarf að vera í My-LocalMachine).</param>
        /// <returns>Skilar SAML token</returns>
        public GenericXmlSecurityToken CreateToken(string userName, string personId, string fullName, List<string> roles, string encryptingCertSubject, string signingCertSubject)
        {
            ClaimsIdentity identity = new ClaimsIdentity(AuthenticationTypes.Federation);
            identity.AddClaim(new Claim(USERNAME, userName));
            identity.AddClaim(new Claim(PERSONID, personId));
            identity.AddClaim(new Claim(FULLNAME, fullName));

            //Setja AuthenticationMethod
            identity.AddClaim(
                        new Claim(
                            ClaimTypes.AuthenticationMethod,
                            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
                            ClaimValueTypes.String,
                            "TestIP"));

            identity.AddClaim(
                new Claim(ClaimTypes.AuthenticationInstant,
                XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddTHH:mm:ss.fffZ"),
                "http://www.w3.org/2001/XMLSchema#dateTime"));

            foreach (string role in roles)
            {
                identity.AddClaim(new Claim(ROLE, role));
            }

            X509Certificate2 encryptingCert = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, encryptingCertSubject);
            X509Certificate2 signingCert = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, signingCertSubject);

            return MakeToken(identity, encryptingCert, signingCert);
        }

        /// <summary>
        /// Býr til SAML token sem inniheldur claim.
        /// </summary>
        /// <param name="userName">Notandanafn sem fer í claim.</param>
        /// <param name="personId">Kennitala sem fer í claim.</param>
        /// <param name="fullName">Nafn notanda sem fer í claim.</param>
        /// <param name="roles">Listi af hlutverkum sem fara í claim.</param>
        /// <param name="encryptingCertPath">Slóð á skilríki sem er notað til að dulrita token </param>
        /// <param name="signingCertPath">Slóð á skilríki sem er notað til að undirrita token</param>
        /// <param name="signingCertPassword">Lykilorð fyrir skilríki sem er notað til að undirrita token</param>
        /// <returns></returns>
        public GenericXmlSecurityToken CreateToken(string userName, string personId, string fullName, List<string> roles, string encryptingCertPath, string signingCertPath, string signingCertPassword)
        {

            ClaimsIdentity identity = new ClaimsIdentity(AuthenticationTypes.Federation);
            identity.AddClaim(new Claim(USERNAME, userName));
            identity.AddClaim(new Claim(PERSONID, personId));
            identity.AddClaim(new Claim(FULLNAME, fullName));

            //Setja AuthenticationMethod
            identity.AddClaim(
                        new Claim(
                            ClaimTypes.AuthenticationMethod,
                            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
                            ClaimValueTypes.String,
                            "TestIP"));

            identity.AddClaim(
                new Claim(ClaimTypes.AuthenticationInstant,
                XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddTHH:mm:ss.fffZ"),
                "http://www.w3.org/2001/XMLSchema#dateTime"));

            

            foreach (string role in roles)
            {
                identity.AddClaim(new Claim(ROLE, role));
            }

            X509Certificate2 encryptingCert = new X509Certificate2(encryptingCertPath);
            X509Certificate2 signingCert = new X509Certificate2(signingCertPath, signingCertPassword);

            return MakeToken(identity, encryptingCert, signingCert);
        }

        private GenericXmlSecurityToken MakeToken(ClaimsIdentity identity, X509Certificate2 encryptingCert, X509Certificate2 signingCert)
        {
            

            var proof = CreateProofDescriptor(encryptingCert);

            var encryptingCredentials = new EncryptedKeyEncryptingCredentials(
                new X509EncryptingCredentials(encryptingCert),
                256,
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc");


            var descriptor = new SecurityTokenDescriptor
            {
                AppliesToAddress = _appliesTo,
                TokenIssuerName = _issuer,

                SigningCredentials = new X509SigningCredentials(signingCert), // signing creds of IdSrv
                EncryptingCredentials = encryptingCredentials,

                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddHours(1)),
                Proof = proof,
                Subject = identity,
                TokenType = "urn:oasis:names:tc:SAML:2.0:assertion"
                
            };

            SecurityTokenHandlerCollection tokenHandler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
            SecurityToken token = tokenHandler.CreateToken(descriptor) as Saml2SecurityToken;

            var outputTokenString = TokenToString(token);

            var handler = new Saml2SecurityTokenHandler();            
            var ar = handler.CreateSecurityTokenReference(token, true);
            var uar = handler.CreateSecurityTokenReference(token, false);
            
            var xmlToken = new GenericXmlSecurityToken(
                            GetElement(outputTokenString),
                            new BinarySecretSecurityToken(proof.GetKeyBytes()),
                            DateTime.UtcNow,
                            DateTime.UtcNow.AddHours(1),
                            ar,
                            uar,
                            new System.Collections.ObjectModel.ReadOnlyCollection<IAuthorizationPolicy>(new List<IAuthorizationPolicy>()));
            
            return xmlToken;
        }

        private string TokenToString(SecurityToken token)
        {
            var genericToken = token as GenericXmlSecurityToken;
            if (genericToken != null)
            {
                return genericToken.TokenXml.OuterXml;
            }

            var handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();

            if (handler.CanWriteToken(token))
            {
                var sb = new StringBuilder(128);
                handler.WriteToken(new XmlTextWriter(new StringWriter(sb)), token);
                return sb.ToString();
            }
            else
            {
                throw new InvalidOperationException("Ekki stuðningur við þessa tegund af tokeni.");
            }
        }

        private SymmetricProofDescriptor CreateProofDescriptor(X509Certificate2 encryptingCertificate)
        {
            return new SymmetricProofDescriptor(
                256,
                new X509EncryptingCredentials(encryptingCertificate));
        }

        private XmlElement GetElement(string xml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc.DocumentElement;
        }
    }
}
