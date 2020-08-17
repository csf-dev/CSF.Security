//
// PasswordAuthenticationServiceTests.cs
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
using NUnit.Framework;
using AutoFixture.NUnit3;

namespace CSF.Security.Tests.Authentication
{
  [TestFixture]
  public class PasswordAuthenticationServiceTests
  {
    [Test,AutoMoqData]
    public void CreateRequest_uses_request_factory([Frozen] IRequestFactory<StubAuthenticationRequest> requestFactory,
                                                   PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                   StubAuthenticationRequest request)
    {
      // Arrange
      Mock.Get(requestFactory)
          .Setup(x => x.CreateRequest(request.EnteredCredentials))
          .Returns(request);

      // Act
      var result = sut.CreateRequest(request.EnteredCredentials);

      // Assert
      Assert.AreSame(request, result, "Correct instance returned");
      Mock.Get(requestFactory).Verify(x => x.CreateRequest(request.EnteredCredentials), Times.Once());
    }

    [Test,AutoMoqData]
    public void RetrieveStoredCredentials_uses_repository([Frozen] IStoredCredentialsRepository repository,
                                                          PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                          StubAuthenticationRequest request,
                                                          StubStoredCredentials stored)
    {
      // Arrange
      Mock.Get(repository)
          .Setup(x => x.GetStoredCredentials(request.EnteredCredentials))
          .Returns(stored);

      request.EnteredCredentials = request.EnteredCredentials;

      // Act
      sut.RetrieveStoredCredentials(ref request);

      // Assert
      Assert.AreSame(stored, request.StoredCredentials, "Stored credentials are set");
      Mock.Get(repository)
          .Verify(x => x.GetStoredCredentials(request.EnteredCredentials), Times.Once());
    }

    [Test,AutoMoqData]
    public void RetrieveStoredCredentials_sets_result_when_credentials_are_not_found([Frozen] IStoredCredentialsRepository repository,
                                                                                     PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                                     StubAuthenticationRequest request)
    {
      // Arrange
      Mock.Get(repository)
          .Setup(x => x.GetStoredCredentials(request.EnteredCredentials))
          .Returns((StubStoredCredentials) null);

      request.EnteredCredentials = request.EnteredCredentials;
      request.Result = null;

      // Act
      sut.RetrieveStoredCredentials(ref request);

      // Assert
      Assert.IsNull(request.StoredCredentials, "Stored credentials are null");
      Assert.NotNull(request.Result, "Result is set");
      Assert.IsFalse(request.Result.CredentialsFound, "Credentials not found");
    }

    [Test,AutoMoqData]
    public void RetrieveVerifier_uses_factory([Frozen] IPasswordVerifierFactory factory,
                                              PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                              StubAuthenticationRequest request,
                                              IPasswordVerifier verifier)
    {
      // Arrange
      Mock.Get(factory)
          .Setup(x => x.GetVerifier(request.CredentialsObject))
          .Returns(verifier);

      // Act
      sut.RetrieveVerifier(ref request);

      // Assert
      Assert.AreSame(verifier, request.Verifier, "Verifier is set");
      Mock.Get(factory)
          .Verify(x => x.GetVerifier(request.CredentialsObject), Times.Once());
    }

    [Test,AutoMoqData]
    public void RetrieveVerifier_does_not_use_factory_when_credentials_object_is_empty([Frozen] IPasswordVerifierFactory factory,
                                                                                       PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                                       StubAuthenticationRequest request)
    {
      // Arrange
      Mock.Get(factory)
          .Setup(x => x.GetVerifier(It.IsAny<object>()))
          .Returns((IPasswordVerifier) null);

      request.CredentialsObject = null;

      // Act
      sut.RetrieveVerifier(ref request);

      // Assert
      Mock.Get(factory)
          .Verify(x => x.GetVerifier(It.IsAny<object>()), Times.Never());
    }

    [Test,AutoMoqData]
    public void RetrieveVerifier_sets_failure_result_when_verifier_cannot_be_created([Frozen] IPasswordVerifierFactory factory,
                                                                                     PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                                     StubAuthenticationRequest request)
    {
      // Arrange
      Mock.Get(factory)
          .Setup(x => x.GetVerifier(request.CredentialsObject))
          .Returns((IPasswordVerifier) null);

      request.Result = null;

      // Act
      sut.RetrieveVerifier(ref request);

      // Assert
      Mock.Get(factory)
          .Verify(x => x.GetVerifier(request.CredentialsObject), Times.Once());
      Assert.NotNull(request.Result, "Result has been set");
      Assert.IsFalse(request.Result.Success, "Result indicates failure");
    }

    [Test,AutoMoqData]
    public void PerformVerification_gets_true_result_when_verification_succeeds(PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                                StubAuthenticationRequest request)
    {
      // Arrange
      Mock.Get(request.Verifier)
          .Setup(x => x.Verify(request.EnteredCredentials, request.CredentialsObject))
          .Returns(true);

      // Act
      sut.PerformVerification(ref request);

      // Assert
      Mock.Get(request.Verifier)
          .Verify(x => x.Verify(request.EnteredCredentials, request.CredentialsObject), Times.Once());
      Assert.IsTrue(request.PasswordVerified, "Password verified");
    }

    [Test,AutoMoqData]
    public void PerformVerification_gets_false_result_when_verification_fails(PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                              StubAuthenticationRequest request)
    {
      // Arrange
      Mock.Get(request.Verifier)
          .Setup(x => x.Verify(request.EnteredCredentials, request.CredentialsObject))
          .Returns(false);

      // Act
      sut.PerformVerification(ref request);

      // Assert
      Mock.Get(request.Verifier)
          .Verify(x => x.Verify(request.EnteredCredentials, request.CredentialsObject), Times.Once());
      Assert.IsFalse(request.PasswordVerified, "Password not verified");
    }


    [Test,AutoMoqData]
    public void PerformVerification_gets_false_result_when_no_verifier_present(PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                               StubAuthenticationRequest request)
    {
      // Arrange
      request.Verifier = null;

      // Act
      sut.PerformVerification(ref request);

      // Assert
      Assert.IsFalse(request.PasswordVerified, "Password verified");
    }

    [Test,AutoMoqData]
    public void DetermineResult_gets_result_when_no_result_set(PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                               StubAuthenticationRequest request)
    {
      // Arrange
      request.Result = null;

      // Act
      sut.DetermineResult(ref request);

      // Assert
      Assert.NotNull(request.Result);
    }

    [Test,AutoMoqData]
    public void DetermineResult_does_not_change_result_when_already_set(PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                        StubAuthenticationRequest request,
                                                                        AuthenticationResult result)
    {
      // Arrange
      request.Result = result;

      // Act
      sut.DetermineResult(ref request);

      // Assert
      Assert.AreSame(result, request.Result);
    }

    [Test,AutoMoqData]
    public void DetermineResult_creates_success_result_when_password_is_verified(PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                                 StubAuthenticationRequest request)
    {
      // Arrange
      request.Result = null;
      request.PasswordVerified = true;

      // Act
      sut.DetermineResult(ref request);

      // Assert
      Assert.IsTrue(request.Result.Success);
    }

    [Test,AutoMoqData]
    public void DetermineResult_creates_failure_result_when_password_is_not_verified(PasswordAuthenticationService<StubAuthenticationRequest> sut,
                                                                                     StubAuthenticationRequest request)
    {
      // Arrange
      request.Result = null;
      request.PasswordVerified = false;

      // Act
      sut.DetermineResult(ref request);

      // Assert
      Assert.IsFalse(request.Result.Success);
    }
  }
}
