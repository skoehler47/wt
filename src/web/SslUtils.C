/*
 * Copyright (C) 2012 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#include <Wt/WConfig.h>

#ifdef WT_WITH_SSL
#ifdef WT_WIN32
#include <Wt/AsioWrapper/ssl.hpp>
#endif // WT_WIN32
#endif // WT_WITH_SSL

#include <Wt/WException.h>

#include "SslUtils.h"

#ifdef WT_WITH_SSL
#include <openssl/ssl.h>

#ifdef WT_WIN32
#include <wincrypt.h>
#endif // WT_WIN32
#endif //WT_WITH_SSL

#ifdef WT_WITH_SSL
namespace {

#ifdef WT_WIN32
void addWindowsCACertificates(asio::ssl::context &ctx) {
  HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
  if (hStore == NULL) {
    return;
  }

  X509_STORE *store = X509_STORE_new();
  PCCERT_CONTEXT pContext = NULL;
  while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
    X509 *x509 = d2i_X509(NULL,
      (const unsigned char **)&pContext->pbCertEncoded,
      pContext->cbCertEncoded);
    if (x509 != NULL) {
      X509_STORE_add_cert(store, x509);
      X509_free(x509);
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);

  SSL_CTX_set_cert_store(ctx.native_handle(), store);
}
#endif // WT_WIN32

}

namespace Wt {
  namespace Ssl {
    std::vector<Wt::WSslCertificate::DnAttribute>
    getDnAttributes(struct X509_name_st *sn)
    {
      std::vector<Wt::WSslCertificate::DnAttribute> retval;

      if (!sn)
        return retval;

      int entries = X509_NAME_entry_count(sn);
      for (int i = 0; i < entries; ++i) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(sn, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        int nid = OBJ_obj2nid(obj);

        std::string value;
        {
          char *s;
          ASN1_STRING_to_UTF8((unsigned char **)(&s), data);
          value = s;
          OPENSSL_free(s);
        }

        Wt::WSslCertificate::DnAttributeName name;
        bool knownAttribute = true;
        switch (nid) {
        case NID_commonName:
          name = Wt::WSslCertificate::CommonName; break;
        case NID_countryName:
          name = Wt::WSslCertificate::CountryName; break;
        case NID_localityName:
          name = Wt::WSslCertificate::LocalityName; break;
        case NID_stateOrProvinceName:
          name = Wt::WSslCertificate::StateOrProvinceName; break;
        case NID_organizationName:
          name = Wt::WSslCertificate::OrganizationName; break;
        case NID_organizationalUnitName:
          name = Wt::WSslCertificate::OrganizationalUnitName; break;
        case NID_givenName:
          name = Wt::WSslCertificate::GivenName; break;
        case NID_surname:
          name = Wt::WSslCertificate::Surname; break;
        case NID_initials:
          name = Wt::WSslCertificate::Initials; break;
        case NID_serialNumber:
          name = Wt::WSslCertificate::SerialNumber; break;
        case NID_title:
          name = Wt::WSslCertificate::Title; break;
        default:
          // extra unknown attributes; ignore them
          knownAttribute = false;
          break;
        }

        if (knownAttribute) {
          Wt::WSslCertificate::DnAttribute dna(name, value);
          retval.push_back(dna);
        }
      }

      return retval;
    }

    WSslCertificate x509ToWSslCertificate(X509 *x509)
    {
      std::vector<Wt::WSslCertificate::DnAttribute> subjectDn
        = getDnAttributes(X509_get_subject_name(x509));
      std::vector<Wt::WSslCertificate::DnAttribute> issuerDn
        = getDnAttributes(X509_get_issuer_name(x509));
      Wt::WDateTime validityStart
        = dateToWDate(X509_get0_notBefore(x509));
      Wt::WDateTime validityEnd
        = dateToWDate(X509_get0_notAfter(x509));

      std::string pemCert = Wt::Ssl::exportToPem(x509);

      return WSslCertificate(subjectDn, issuerDn, validityStart, validityEnd, pemCert);
    }

    Wt::WDateTime dateToWDate(const ASN1_TIME *date)
    {
      // Got my wisdom from ITU-T rec X.680 (07/2002) and RFC 3280
      Wt::WDateTime retval;

      if (!date)
        return retval;

      switch (date->type) {
      case V_ASN1_UTCTIME:
        {
          // decode asn.1 Universal time string
          // Format further restricted by RFC 3280, section 4.1.2.5.1
          int len = date->length;
          const char *v = (const char *)date->data;
          if (len == 13) {
            retval =
              Wt::WDateTime::fromString(std::string(v, v + 12),
                                        "yyMMddHHmmss");
          }
        }
        break;
      case V_ASN1_GENERALIZEDTIME:
        {
          // decode asn.1 Universal time string
          // Format further restricted by RFC 3280, section 4.1.2.5.1
          int len = date->length;
          const char *v = (const char *)date->data;
          if (len == 15) {
            retval =
              Wt::WDateTime::fromString(std::string(v, v + 12),
                                        "yyyyMMddHHmmss");
          }
        }
        break;
      default:
        break;
      }

      return retval;
    }

    std::string exportToPem(X509 *x509)
    {
      std::string bio;

      if (!x509)
        return bio;

      BIO *bioMem = BIO_new(BIO_s_mem());
      if (!PEM_write_bio_X509(bioMem, x509)) {
        // error
      } else {
        char *thePem;
        int pemLength = BIO_get_mem_data(bioMem, &thePem);
        bio = std::string(thePem, thePem + pemLength);
      }
      BIO_free_all(bioMem);
      return bio;
    }

    extern X509 *readFromPem(const std::string &pem)
    {
      BIO *bio;
      X509 *certificate;

      bio = BIO_new(BIO_s_mem());
      BIO_puts(bio, pem.c_str());
      certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);

      BIO_free_all(bio);

      return certificate;
    }

    asio::ssl::context createSslContext(asio::io_service &io_service,
                                        bool addCACerts)
    {
#if defined(WT_ASIO_IS_BOOST_ASIO)
      (void)io_service;
      asio::ssl::context context(asio::ssl::context::tls);
#elif defined(WT_ASIO_IS_STANDALONE_ASIO)
      (void)io_service;
      asio::ssl::context context(asio::ssl::context::sslv23);
#endif

      long sslOptions = asio::ssl::context::no_sslv2 |
                        asio::ssl::context::no_sslv3 |
                        asio::ssl::context::no_tlsv1;

      sslOptions |= asio::ssl::context::no_tlsv1_1;

      context.set_options(sslOptions);

      if (addCACerts) {
        context.set_default_verify_paths();
#ifdef WT_WIN32
        addWindowsCACertificates(context);
#endif // WT_WIN32
      }

      return context;
    }

    EVP_PKEY* readPrivateKeyFromFile(const std::string& path)
    {
      const auto file = std::fopen(path.c_str(), "rb");
      if (!file) {
        return nullptr;
      }
      const auto pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
      std::fclose(file);
      return pkey;
    }

    std::string rs256(EVP_PKEY* pkey, const std::string& message)
    {
      auto ctx = EVP_MD_CTX_new();
      int status = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
      if (status != 1) {
        throw WException("RS256 digest failed: could not initialize!");
      }
      status = EVP_DigestSignUpdate(ctx, message.c_str(), message.size());
      if (status != 1) {
        throw WException("RS256 digest failed: EVP_DigestSignUpdate failed");
      }
      std::size_t slen{};
      status = EVP_DigestSignFinal(ctx, nullptr, &slen);
      if (status != 1) {
        throw WException("RS256 digest failed: EVP_DigestSignFinal failed");
      }
      std::string result(slen, '\0');
      status = EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char *>(&result[0]), &slen);
      if (status != 1) {
        throw WException("RS256 digest failed: EVP_DigestSignFinal failed");
      }
      EVP_MD_CTX_free(ctx);
      return result;
    }
  }
}
#endif //WT_WITH_SSL
