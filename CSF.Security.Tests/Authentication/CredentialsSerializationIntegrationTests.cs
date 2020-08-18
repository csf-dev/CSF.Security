//
// CredentialsSerializationIntegrationTests.cs
//
// Author:
//       Craig Fowler <craig@csf-dev.com>
//
// Copyright (c) 2020 Craig Fowler
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using CSF.Security.Authentication;
using CSF.Security.Tests.Stubs;
using NUnit.Framework;

namespace CSF.Security.Tests.Authentication
{
    [TestFixture]
    public class CredentialsSerializationIntegrationTests
    {
        /// <summary>
        /// Some credentials created using the old mechanism of indicating the Assebmly-Qualified type name.
        /// </summary>
        const string ValidOldStyleCredentials = "CSF.Security.Tests.Stubs.StubCredentials, CSF.Security.Tests:{\"Key\":\"My key\",\"Salt\":\"Salty goodness\",\"InitialisationNumber\":5}";

        /// <summary>
        /// Some credentials created using the new mechanism of indicating the Assebmly-Qualified type name.
        /// </summary>
        const string ValidNewStyleCredentials = "{\"$type\":\"CSF.Security.Tests.Stubs.StubCredentials, CSF.Security.Tests\",\"Key\":\"My key\",\"Salt\":\"Salty goodness\",\"InitialisationNumber\":5}";

        [Test]
        public void Deserialize_can_read_credentials_which_use_a_type_prefix()
        {
            var sut = GetSut();
            var result = sut.Deserialize(ValidOldStyleCredentials);

            Assert.That(result, Is.InstanceOf<StubCredentials>(), "Expected type");
            var typedResult = (StubCredentials)result;
            Assert.That(typedResult.InitialisationNumber, Is.EqualTo(5), nameof(StubCredentials.InitialisationNumber));
            Assert.That(typedResult.Key, Is.EqualTo("My key"), nameof(StubCredentials.Key));
            Assert.That(typedResult.Salt, Is.EqualTo("Salty goodness"), nameof(StubCredentials.Salt));
        }

        [Test]
        public void Deserialize_can_read_credentials_which_use_a_JSON_type_property()
        {
            var sut = GetSut();
            var result = sut.Deserialize(ValidNewStyleCredentials);

            Assert.That(result, Is.InstanceOf<StubCredentials>(), "Expected type");
            var typedResult = (StubCredentials)result;
            Assert.That(typedResult.InitialisationNumber, Is.EqualTo(5), nameof(StubCredentials.InitialisationNumber));
            Assert.That(typedResult.Key, Is.EqualTo("My key"), nameof(StubCredentials.Key));
            Assert.That(typedResult.Salt, Is.EqualTo("Salty goodness"), nameof(StubCredentials.Salt));
        }

        [Test]
        public void Serialize_writes_credentials_using_a_JSON_type_property()
        {
            var credentials = new StubCredentials
            {
                InitialisationNumber = 5,
                Key = "My key",
                Salt = "Salty goodness",
            };
            var sut = GetSut();
            var result = sut.Serialize(credentials);

            Assert.That(result, Does.Match(@"\b\$type\b"), "Includes a $type element");
            Assert.That(result, Does.Match(@"^\{"), "Begins with an open-brace");
        }

        ICredentialsSerializer GetSut()
        {
            throw new NotImplementedException();
        }
    }
}
