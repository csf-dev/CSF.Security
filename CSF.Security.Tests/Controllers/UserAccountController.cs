//
// UserAccountController.cs
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
using CSF.Security.Authentication;
using CSF.Security.Tests.Stubs;
using Moq;

namespace CSF.Security.Tests.Controllers
{
  public class UserAccountController
  {
    #region constants

    internal const int IterationCount = 10000;

    #endregion

    #region fields

    readonly Mock<IStoredCredentialsRepository> repository;
    readonly ICredentialsCreator credentialsCreator;
    readonly ICredentialsSerializer credentialsSerializer;

    #endregion

    #region properties

    public IStoredCredentialsRepository Repository => repository.Object;

    #endregion

    #region methods

    public void SetupNoUserAccount(string username)
    {
      repository
        .Setup(x => x.GetStoredCredentials(It.Is<UsernameAndPassword>(u => u.Username == username)))
        .Returns((IStoredCredentials) null);
    }

    public void SetupUserAccount(string username, string password)
    {
      var credentials = new CredentialsWithPassword { Password = password };

      var credentialsObject = credentialsCreator.CreateCredentials(credentials);
      var serialized = credentialsSerializer.Serialize(credentialsObject);
      var stored = new StoredUserAccount {
        Username = username,
        SerializedCredentials = serialized
      };

      repository
        .Setup(x => x.GetStoredCredentials(It.Is<UsernameAndPassword>(u => u.Username == username)))
        .Returns(stored);
    }

    #endregion

    #region constructor

    public UserAccountController()
    {
      repository = new Mock<IStoredCredentialsRepository>();
      credentialsCreator = new PBKDF2PasswordVerifier(iterationCount: IterationCount);
      credentialsSerializer = new JsonCredentialsSerializer();
    }

    #endregion
  }
}
