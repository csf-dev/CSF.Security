//
// TestPBKDF2CredentialsFactory.cs
//
// Author:
//       Craig Fowler <craig@csf-dev.com>
//
// Copyright (c) 2017 Craig Fowler
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
using CSF.Security;
using Moq;
using NUnit.Framework;

namespace Test.CSF
{
  [TestFixture]
  public class TestPBKDF2CredentialsFactory
  {
    #region fields

    Mock<IBinaryKeyCreator> _keyCreator;
    PBKDF2CredentialsFactory _sut;
    byte[] _salt, _key, _password;

    #endregion

    #region setup

    [SetUp]
    public void Setup()
    {
      _salt       = new byte[] { 1, 2, 3 };
      _key        = new byte[] { 4, 5, 6 };
      _password   = new byte[] { 7, 8, 9 };
      _keyCreator = new Mock<IBinaryKeyCreator>();
      _sut = new PBKDF2CredentialsFactory((arg) => _keyCreator.Object);

      _keyCreator.Setup(x => x.CreateRandomSalt(It.IsAny<int>())).Returns(_salt);
      _keyCreator
        .Setup(x => x.CreateKey(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>()))
        .Returns(_key);
    }

    #endregion

    #region tests

    [Test]
    public void GetCredentials_uses_iteration_count_to_construct_service()
    {
      // Arrange
      bool countUsed = false;
      Func<int,IBinaryKeyCreator> creationFunc = (arg) => {
        countUsed = true;
        return _keyCreator.Object;
      };
      var sut = new PBKDF2CredentialsFactory(creationFunc);

      // Act
      sut.GetCredentials(Mock.Of<IPBKDF2CredentialsInfo>());

      // Assert
      Assert.IsTrue(countUsed);
    }

    [Test]
    public void GetCredentials_uses_service_to_create_salt()
    {
      // Act
      _sut.GetCredentials(Mock.Of<IPBKDF2CredentialsInfo>(x => x.SaltLength == 5));

      // Assert
      _keyCreator.Verify(x => x.CreateRandomSalt(5), Times.Once());
    }

    [Test]
    public void GetCredentials_uses_service_to_create_key()
    {
      // Act
      _sut.GetCredentials(Mock.Of<IPBKDF2CredentialsInfo>(x => x.KeyLength == 5
                                                               && x.GetPasswordAsByteArray() == _password));

      // Assert
      _keyCreator.Verify(x => x.CreateKey(_password, _salt, 5), Times.Once());
    }

    [Test]
    public void GetCredentials_returns_correct_result()
    {
      // Act
      var result = _sut.GetCredentials(Mock.Of<IPBKDF2CredentialsInfo>(x => x.IterationCount == 5));

      // Assert
      Assert.AreEqual(_key, result.GetKeyAsByteArray(), "Key");
      Assert.AreEqual(_salt, result.GetSaltAsByteArray(), "Salt");
      Assert.AreEqual(5, result.IterationCount, "Iteration count");
    }

    #endregion
  }
}
