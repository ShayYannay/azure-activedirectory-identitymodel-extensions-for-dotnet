//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tests;
using Xunit;

using ALG = Microsoft.IdentityModel.Tokens.SecurityAlgorithms;
using KEY = Microsoft.IdentityModel.Tests.KeyingMaterial;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class ECDsaTests
    {
#if !WINDOWS && NETCOREAPP2_0
        [Theory, MemberData(nameof(CreateECDsaFromJsonWebKeyTheoryData))]
        public void CreateECDsa(JsonWebKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateECDsa", theoryData);
            try
            {
                var jsonWebKey = new JsonWebKey
                {
                    Crv = theoryData.Crv,
                    X = theoryData.X,
                    Y = theoryData.Y,
                    D = theoryData.D,
                };

                jsonWebKey.CreateECDsa(theoryData.UsePrivateKey);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonWebKeyTheoryData> CreateECDsaFromJsonWebKeyTheoryData
        {
            get => new TheoryData<JsonWebKeyTheoryData>
            {
                new JsonWebKeyTheoryData {
                    First = true,
                    UsePrivateKey = false,
                    Crv = null,
                    X = KEY.JsonWebKeyP256.X,
                    Y = KEY.JsonWebKeyP256.Y,
                    TestId = "null_Crv",
                    ExpectedException = ExpectedException.ArgumentNullException(),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-255",
                    X = KEY.JsonWebKeyP256.X,
                    Y = KEY.JsonWebKeyP256.Y,
                    TestId = "unknown_Crv",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", typeof(ArgumentException)),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-256",
                    X = null,
                    Y = KEY.JsonWebKeyP256.Y,
                    TestId = "null_X_param",
                    ExpectedException = ExpectedException.ArgumentNullException(),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X,
                    Y = null,
                    TestId = "null_Y_param",
                    ExpectedException = ExpectedException.ArgumentNullException(),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = true,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X,
                    Y = KEY.JsonWebKeyP256.Y,
                    D = null,
                    TestId = "null_D_param",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", typeof(ArgumentNullException)),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X + "_dummy_data",
                    Y = KEY.JsonWebKeyP256.Y,
                    TestId = "X_longer_than_Y",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", typeof(CryptographicException)),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X.Remove(KEY.JsonWebKeyP256.X.Length - 1),
                    Y = KEY.JsonWebKeyP256.Y,
                    TestId = "X_shorter_than_Y",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", typeof(CryptographicException)),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X,
                    Y = KEY.JsonWebKeyP256.Y + "_dummy_data",
                    TestId = "Y_longer_than_X",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", typeof(CryptographicException)),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = true,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X,
                    Y = KEY.JsonWebKeyP256.Y,
                    D = KEY.JsonWebKeyP256.D + "_dummy_data",
                    TestId = "D_longer_than_X_Y",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", typeof(CryptographicException)),
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = true,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP384.X,
                    Y = KEY.JsonWebKeyP384.Y,
                    D = KEY.JsonWebKeyP384.D,
                    TestId = "params_more_bytes_than_curve",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", ignoreInnerException: true), // throws different inner exceptions on different platforms
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = true,
                    Crv = "P-256",
                    X = "",
                    Y = "",
                    D = "",
                    TestId = "empty_params",
                    ExpectedException = ExpectedException.CryptographicException("IDX10689:", ignoreInnerException: true), // throws different inner exceptions on different platforms
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X,
                    Y = KEY.JsonWebKeyP256.Y,
                    D = null,
                    TestId = "success_null_D_no_private_key",
                },
                new JsonWebKeyTheoryData {
                    UsePrivateKey = false,
                    Crv = "P-256",
                    X = KEY.JsonWebKeyP256.X,
                    Y = KEY.JsonWebKeyP256.Y,
                    D = KEY.JsonWebKeyP256.D,
                    TestId = "successful_call",
                },
            };
        }

        [Theory, MemberData(nameof(JsonWebKeyAsymmetricSignAndVerifyTheoryData))]
        public void JsonWebKeyAsymmetricSignAndVerify(SignatureProviderTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.AsymmetricSignAndVerify", theoryData);
            try
            {
                var signatureProviderVerify = theoryData.CryptoProviderFactory.CreateForVerifying(theoryData.VerifyKey, theoryData.VerifyAlgorithm);
                var signatureProviderSign = theoryData.CryptoProviderFactory.CreateForSigning(theoryData.SigningKey, theoryData.SigningAlgorithm);
                var bytes = Encoding.UTF8.GetBytes("GenerateASignature");
                var signature = signatureProviderSign.Sign(bytes);
                if (!signatureProviderVerify.Verify(bytes, signature))
                    throw new CryptographicException("SignatureProvider.Verify.Failed");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureProviderTheoryData> JsonWebKeyAsymmetricSignAndVerifyTheoryData
        {
            get => new TheoryData<SignatureProviderTheoryData>
            {
                new SignatureProviderTheoryData{
                    First = true,
                    SigningAlgorithm = ALG.EcdsaSha256,
                    VerifyAlgorithm = ALG.EcdsaSha256,
                    SigningKey = KEY.JsonWebKeyP256,
                    VerifyKey = KEY.JsonWebKeyP256_Public,
                    TestId = "JsonWebKeyEcdsa256",
                },
                new SignatureProviderTheoryData{
                    SigningAlgorithm = ALG.EcdsaSha384,
                    VerifyAlgorithm = ALG.EcdsaSha384,
                    SigningKey = KEY.JsonWebKeyP384,
                    VerifyKey = KEY.JsonWebKeyP384_Public,
                    TestId = "JsonWebKeyEcdsa384",
                },
                new SignatureProviderTheoryData{
                    SigningAlgorithm = ALG.EcdsaSha512,
                    VerifyAlgorithm = ALG.EcdsaSha512,
                    SigningKey = KEY.JsonWebKeyP521,
                    VerifyKey = KEY.JsonWebKeyP521_Public,
                    TestId = "JsonWebKeyEcdsa521",
                },
                new SignatureProviderTheoryData{
                    SigningAlgorithm = ALG.EcdsaSha256,
                    VerifyAlgorithm = ALG.EcdsaSha256,
                    SigningKey = KEY.JsonWebKeyP256_BadPrivateKey,
                    VerifyKey = KEY.JsonWebKeyP256_Public,
                    TestId = "JsonWebKeyEcdsaError",
                    ExpectedException = ExpectedException.CryptographicException(ignoreInnerException: true) // throws different inner exceptions on different platforms
                }
            };
        }

        public class JsonWebKeyTheoryData : TheoryDataBase
        {
            public string Crv { get; set; }

            public string D { get; set; }

            public bool UsePrivateKey { get; set; }

            public string X { get; set; }

            public string Y { get; set; }
        }
#endif
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
