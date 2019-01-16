using System;
using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using RB.GatewayTester.AccountsReference;
using RB.Torg.B2BAccounts.SimpleTesterCodeOnly45.WSTrust;

namespace RB.GatewayTester
{
    
    class Program
    {
        //Slóð á þjónustu
        private static String _serviceUrl = "https://gw.test.rb.is/b2b/v1/accounts";

        //Slóða á ADFS
        private static String _adfsUrl = "https://sts.test.rb.is/adfs/services/trust/13/IssuedTokenMixedSymmetricBasic256";
        
        //AppliesTo
        //Sækir bearer token s.s. token sem er einungis undirritað     
        private static String _adfsAppliesTo = "urn:rbws.test.rb.is/signingonly";       

        private static SecurityToken _token = null;
        private static ChannelFactory<IAccounts> factory = null;

        static void Main(string[] args)
        {
            //Þetta sýnidæmi sér sjálft um að smíða SAML token.  Eðlilegra væri að Security Token Service (STS) myndi gefa út SAML tokenið en til að halda
            //uppsetningu í lágmarki þá er þetta gert svona.  Kemur alveg til greina að smíða SAML token með þessum hætti s.s. inn í application kóða en þá þarf
            //að passa upp á private lykilinn sem er notaður til að undirrita tokenið.

            TokenMaker tm = new TokenMaker(
                appliesTo: "http://sts.test.rb.is/adfs/services/trust",
                issuer: "uri:rbtest");


            //Hér eru skilríkin lesin úr skrá, eðlilegra væri að lesa skilríkin úr "Certificate Store" á vélinni eins og má sjá hér fyrir neðan en til einföldunar
            //þá eru skilríkin lesin úr skrá.
            #region Skilríki lesin úr skrá
            GenericXmlSecurityToken token = tm.CreateToken(
                           userName: "RB Testnotandi",
                           personId: "4701110540",
                           fullName: "Reiknistofa Bankanna",
                           roles: new List<string>() { "5000-getdepaccount-test" },
                           encryptingCertPath: ".\\Certificate\\rb_adfs_test_token_operations_public.cer",
                           signingCertPath: ".\\Certificate\\rbtest.rb.is.pfx",
                           signingCertPassword: "rbtest");

            #endregion

            //Hér eru skilríkin lesin úr "Certificate Store".  Ef þessi kóði er notaður í staðinn fyrir kóðan hér fyrir ofan þá þarf að setja skilríkin undir
            //Local Computer - Personal.
            #region Skilríki lesin úr certificate store
            /*
            GenericXmlSecurityToken token = tm.CreateToken(
                userName: "RB Testnotandi",
                personId: "4701110540",
                fullName: "Reiknistofa Bankanna",
                roles: new List<string>() { "5000-getdepaccount-test" },
                encryptingCertSubject: "SubjectForEncryptionCertificate",
                signingCertSubject: "SubjectForSigningCertificate");            
            */
            #endregion

            //ATH. þegar notuð eru eigin skilríki til að kalla á þjónustur RB þá þarf að láta RB fá public lykilinn fyrir það skilríki til að hægt sé að
            //staðfesta undirritunina.  Einnig þarf RB að fá að vita hvaða issuer identifier er notaður (settur í smiðnum fyrir TokenMaker).

            _token = token;

            SecurityToken adfsToken = GetTorgToken(token,_adfsUrl,_adfsAppliesTo);
            
            _token = adfsToken;

            Console.ForegroundColor = ConsoleColor.Green;
            List<String> reikningar = new List<string>();

            Echo();

            //Sækja upplýsingar um reikning sem á að leggja inn á
            GetDepositAccount("GetDepositAccount", "010126072545", "");
            GetDepositAccount("GetDepositAccount", "017126033607", "");

            Console.WriteLine();
            Console.WriteLine("Done...");
            Console.ReadKey();
        }

        private static void Echo()
        {
            Console.WriteLine("-------------------------------------------------------------------------------");
            Console.WriteLine("Kalla á Echo");
            try
            {
                EchoInfo info = new EchoInfo();

                var channel = GetChannel();

                info = channel.Echo();

            }
            catch (FaultException<CustomFaultException> e)
            {
                Console.WriteLine("Villa:");
                Console.WriteLine("Message: {0}", e.Message);
                Console.WriteLine("GeneralErrorCode: {0}", e.Detail.GeneralErrorCode);
                Console.WriteLine("GeneralErrorText: {0}", e.Detail.GeneralErrorText);
                Console.WriteLine("BanksErrorCode: {0}", e.Detail.BanksErrorCode);
                Console.WriteLine("BanksErrorText: {0}", e.Detail.BanksErrorText);
            }
            catch (Exception e)
            {
                Console.WriteLine("Message: {0}", e.Message);
            }
        }

        private static void GetDepositAccount(String info, String accountID, String accountOwnerID)
        {
            Console.WriteLine("-------------------------------------------------------------------------------");
            Console.WriteLine(info);
            Console.WriteLine("Kalla á Accounts.GetDepositAccount: {0} ", accountID);
            try
            {
                DepositAccountInfo accountInfo = new DepositAccountInfo();
                DepositAccountQuery q = new DepositAccountQuery();

                q.AccountID = accountID;

                if (accountOwnerID != "")
                {
                    q.AccountOwnerID = accountOwnerID;
                }

                var channel = GetChannel();
                accountInfo = channel.GetDepositAccount(q);

                Console.WriteLine("Reikningur fannst");
                Console.WriteLine("Reikningur: {0} Kennitala: {1}", accountInfo.AccountID, accountInfo.AccountOwner.AccountOwnerID);
            }
            catch (FaultException<CustomFaultException> e)
            {
                Console.WriteLine("Villa:");
                Console.WriteLine("Message: {0}", e.Message);
                Console.WriteLine("GeneralErrorCode: {0}", e.Detail.GeneralErrorCode);
                Console.WriteLine("GeneralErrorText: {0}", e.Detail.GeneralErrorText);
                Console.WriteLine("BanksErrorCode: {0}", e.Detail.BanksErrorCode);
                Console.WriteLine("BanksErrorText: {0}", e.Detail.BanksErrorText);
            }
            catch (Exception e)
            {
                Console.WriteLine("Message: {0}", e.Message);
            }
        }

        /// <summary>
        /// Sækja SAML token.  Sent inn annað SAML token.
        /// </summary>
        /// <param name="actAsToken">SAML token</param>
        /// <param name="sts">Slóð á STS</param>
        /// <param name="appliesTo">Einkenni þess sem fær tokenið (Relying party identifier)</param>
        /// <returns>SAML token</returns>
        private static SecurityToken GetTorgToken(SecurityToken token, string url, string appliesTo)
        {
            Uri uri = new Uri(url);

            EndpointAddress epaddr = new EndpointAddress(uri);


            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointReference(appliesTo),
                KeyType = KeyTypes.Bearer //Sækir bearer token
            };

            IssuedTokenWSTrustBinding binding = new IssuedTokenWSTrustBinding();
            binding.SecurityMode = SecurityMode.TransportWithMessageCredential;


            var factory = new WSTrustChannelFactory(
                binding,
                epaddr);

            factory.TrustVersion = TrustVersion.WSTrust13;
            factory.Credentials.SupportInteractive = false;
            factory.Credentials.UseIdentityConfiguration = true;
            

            var channel = factory.CreateChannelWithIssuedToken(token);

            return channel.Issue(rst);
        }

        /// <summary>
        /// Sækja channel
        /// </summary>
        /// <returns>Skilar Interface-i fyrir þjónustu</returns>
        private static IAccounts GetChannel()
        {
            //Stilla binding, hér er notað TransportWithMessageCredentials
            var b = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            b.Security.Message.NegotiateServiceCredential = false;
            b.Security.Message.EstablishSecurityContext = false;
            b.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;
            EndpointAddress epaddr = new EndpointAddress(new Uri(_serviceUrl));

            //Endurnýta factory
            if (factory == null)
            {
                factory = new ChannelFactory<IAccounts>(b, epaddr);
                factory.Credentials.SupportInteractive = false;
            }

            return factory.CreateChannelWithIssuedToken(_token);

        }
    }
}

