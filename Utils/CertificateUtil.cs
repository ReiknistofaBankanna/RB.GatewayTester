﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace RB.GatewayTester
{
    /// <summary>
    /// Hjálparklasi fyrir skilríkjameðöndlun.
    /// </summary>
    public class CertificateUtil
    {

        public static X509Certificate2 GetCertificate(string path, string password = "")
        {
            X509Certificate2 cert = null;
            if (password == "")
                cert = new X509Certificate2(path);
            else
            {
                cert = new X509Certificate2(path, password);
            }

            return cert;
        }


        public static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, string subjectName)
        {
            X509Store store = new X509Store(name, location);
            X509Certificate2Collection certificates = null;
            store.Open(OpenFlags.ReadOnly);

            try
            {
                X509Certificate2 result = null;

                certificates = store.Certificates;

                for (int i = 0; i < certificates.Count; i++)
                {
                    X509Certificate2 cert = certificates[i];

                    if (cert.SubjectName.Name.ToLower() == subjectName.ToLower())
                    {
                        if (result != null)
                            throw new ApplicationException(string.Format("There are multiple certificate for subject Name {0}", subjectName));

                        result = new X509Certificate2(cert);
                    }
                }

                if (result == null)
                {
                    throw new ApplicationException(string.Format("No certificate was found for subject Name {0}", subjectName));
                }

                return result;
            }
            finally
            {
                if (certificates != null)
                {
                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];
                        cert.Reset();
                    }
                }

                store.Close();
            }
        }

        /// <summary>
        /// Sækja skilríki í store eftir thumbprinti.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="location"></param>
        /// <param name="thumbprint"></param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateByThumbprint(StoreName name, StoreLocation location, string thumbprint)
        {
            X509Store store = new X509Store(name, location);
            X509Certificate2Collection certificates = null;
            store.Open(OpenFlags.ReadOnly);

            try
            {
                X509Certificate2 result = null;

                //
                // Every time we call store.Certificates property, a new collection will be returned.
                //
                certificates = store.Certificates;

                for (int i = 0; i < certificates.Count; i++)
                {
                    X509Certificate2 cert = certificates[i];

                    if (cert.Thumbprint.ToUpper() == thumbprint.ToUpper())
                    {
                        if (result != null)
                            throw new ApplicationException(string.Format("There are multiple certificate for thumbprint Name {0}", thumbprint));

                        result = new X509Certificate2(cert);
                    }
                }

                if (result == null)
                {
                    throw new ApplicationException(string.Format("No certificate was found for thumbprint {0}", thumbprint));
                }

                return result;
            }
            finally
            {
                if (certificates != null)
                {
                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];
                        cert.Reset();
                    }
                }

                store.Close();
            }
        }
    }
}