//
// PasswordAuthenticationService.cs
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
namespace CSF.Security.Authentication
{
  public class PasswordAuthenticationService<TRequest> : IPasswordAuthenticationService
    where TRequest : IPasswordAuthenticationRequest
  {
    #region fields

    readonly IRequestFactory<TRequest> requestFactory;
    readonly IStoredCredentialsRepository repository;
    readonly IPasswordVerifierFactory verifierFactory;
    readonly ICredentialsSerializer credentialsSerializer;

    #endregion

    #region public API

    public virtual IAuthenticationResult Authenticate(IEnteredPassword enteredPassword)
    {
      if(ReferenceEquals(enteredPassword, null))
      {
        throw new ArgumentNullException(nameof(enteredPassword));
      }

      var request = CreateRequest(enteredPassword);

      OnBeforeGetStoredCredentials(request);
      RetrieveStoredCredentials(ref request);
      RetrieveDeserializedCredentials(ref request);
      RetrieveVerifier(ref request);
      OnBeforeVerifyPassword(request);
      PerformVerification(ref request);
      OnAfterVerifyPassword(request);
      DetermineResult(ref request);
      OnAuthenticationComplete(request);

      return request.Result;
    }

    #endregion

    #region events

    public event EventHandler<AuthenticationStepEventArgs<TRequest>> BeforeGetStoredCredentials;

    public event EventHandler<AuthenticationStepEventArgs<TRequest>> BeforeVerifyPassword;

    public event EventHandler<AuthenticationStepEventArgs<TRequest>> AfterVerifyPassword;

    public event EventHandler<AuthenticationStepEventArgs<TRequest>> SuccessfulAuthentication;

    public event EventHandler<AuthenticationStepEventArgs<TRequest>> FailedAuthentication;

    #endregion

    #region methods

    public virtual TRequest CreateRequest(IEnteredPassword enteredPassword)
    {
      return requestFactory.CreateRequest(enteredPassword);
    }

    public virtual void RetrieveStoredCredentials(ref TRequest request)
    {
      request.StoredCredentials = GetStoredCredentials(request);

      if(request.StoredCredentials == null)
      {
        request.Result = GetCannotFindCredentialsResult(request);
      }
    }

    public virtual void RetrieveDeserializedCredentials(ref TRequest request)
    {
      if(request.StoredCredentials == null)
      {
        return;
      }

      if(request.CredentialsObject == null)
      {
        request.CredentialsObject = credentialsSerializer.Deserialize(request.StoredCredentials.SerializedCredentials);
      }
    }

    public virtual void RetrieveVerifier(ref TRequest request)
    {
      if(request.CredentialsObject == null)
      {
        return;
      }

      request.Verifier = GetVerifier(request);
      if(request.Verifier == null)
      {
        request.Result = GetCannotCreateVerifierResult(request);
      }
    }

    public virtual void PerformVerification(ref TRequest request)
    {
      if(request.Verifier == null)
      {
        request.PasswordVerified = false;
        return;
      }

      request.PasswordVerified = VerifyPassword(request);
    }

    public virtual void DetermineResult(ref TRequest request)
    {
      if(request.Result != null)
      {
        return;
      }

      request.Result = GetVerificationResult(request);
    }

    public virtual IPasswordVerifier GetVerifier(TRequest request)
    {
      return verifierFactory.GetVerifier(request.CredentialsObject);
    }

    public virtual IStoredCredentials GetStoredCredentials(TRequest request)
    {
      return repository.GetStoredCredentials(request.EnteredCredentials);
    }

    public virtual bool VerifyPassword(TRequest request)
    {
      return request.Verifier.Verify(request.EnteredCredentials, request.StoredCredentials);
    }

    public virtual IAuthenticationResult GetCannotFindCredentialsResult(TRequest request)
    {
      return new AuthenticationResult(false, false);
    }

    public virtual IAuthenticationResult GetCannotCreateVerifierResult(TRequest request)
    {
      return new AuthenticationResult(false, true);
    }

    public virtual IAuthenticationResult GetVerificationResult(TRequest request)
    {
      return new AuthenticationResult(request.PasswordVerified, false);
    }

    #endregion

    #region event invokers

    protected virtual void OnBeforeGetStoredCredentials(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      BeforeGetStoredCredentials?.Invoke(this, args);
    }

    protected virtual void OnBeforeVerifyPassword(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      BeforeVerifyPassword?.Invoke(this, args);
    }

    protected virtual void OnAfterVerifyPassword(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      AfterVerifyPassword?.Invoke(this, args);
    }

    protected virtual void OnSuccessfulAuthentication(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      SuccessfulAuthentication?.Invoke(this, args);
    }

    protected virtual void OnFailedAuthentication(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      FailedAuthentication?.Invoke(this, args);
    }

    protected virtual void OnAuthenticationComplete(TRequest request)
    {
      if(request.Result != null && request.Result.Success)
      {
        OnSuccessfulAuthentication(request);
      }
      else
      {
        OnFailedAuthentication(request);
      }
    }

    #endregion

    #region constructor

    public PasswordAuthenticationService(IRequestFactory<TRequest> requestFactory,
                                         IStoredCredentialsRepository repository,
                                         IPasswordVerifierFactory verifierFactory,
                                         ICredentialsSerializer serializer)
    {
      if(serializer == null)
        throw new ArgumentNullException(nameof(serializer));
      if(verifierFactory == null)
        throw new ArgumentNullException(nameof(verifierFactory));
      if(repository == null)
        throw new ArgumentNullException(nameof(repository));
      if(requestFactory == null)
        throw new ArgumentNullException(nameof(requestFactory));

      this.requestFactory = requestFactory;
      this.repository = repository;
      this.verifierFactory = verifierFactory;
      this.credentialsSerializer = serializer;
    }

    #endregion
  }
}
