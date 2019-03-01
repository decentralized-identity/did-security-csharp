using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using Xunit;

namespace did_security_csharp.Tests
{
    public class PairwiseRSA
    {
        class ReferenceData
        {
            public string pwid { set; get; }
            public string key { set;  get; }
        }

        [Fact]
        public void CheckReferenceKeys()
        {
            byte[] seed = Encoding.UTF8.GetBytes("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
            string did = "abcdef";

            var assembly = typeof(PairwiseEC).Assembly;
            Stream resource = assembly.GetManifestResourceStream("did_security_csharp_tests.Pairwise.RSA.json");

            ReferenceData[] items = null;
            string json = null;
            using (StreamReader r = new StreamReader(resource))
            {
                json = r.ReadToEnd();
                items = JsonConvert.DeserializeObject<ReferenceData[]>(json);
            }

            foreach (var item in items)
            {
                PairwiseKey pwKey = new PairwiseKey(did, item.pwid);
                dynamic jwk = pwKey.generate(seed, 1024, "RSA");
                Assert.Equal(item.key, jwk.d);
            }
        }
    }
}
