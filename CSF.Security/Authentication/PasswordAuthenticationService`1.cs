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
  /// <summary>
  /// Implementation of <see cref="IPasswordAuthenticationService"/> which provides authentication using a
  /// pipeline-like flow.
  /// </summary>
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

    /// <summary>
    /// Authenticate using the given password, and return the outcome.
    /// </summary>
    /// <param name="enteredPassword">Entered password.</param>
    public virtual IAuthenticationResult Authenticate(IPassword enteredPassword)
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

    /// <summary>
    /// Occurs before the stored credentials are retrieved from a repository.
    /// </summary>
    public event EventHandler<AuthenticationStepEventArgs<TRequest>> BeforeGetStoredCredentials;

    /// <summary>
    /// Occurs before the deserialized credentials are verified.
    /// </summary>
    public event EventHandler<AuthenticationStepEventArgs<TRequest>> BeforeVerifyPassword;

    /// <summary>
    /// Occurs after the deserialized credentials are verified but before the final result is decided-upon.
    /// </summary>
    public event EventHandler<AuthenticationStepEventArgs<TRequest>> AfterVerifyPassword;

    /// <summary>
    /// Occurs once a final result has been decided-upon, and where that result is that authentication is a success.
    /// </summary>
    public event EventHandler<AuthenticationStepEventArgs<TRequest>> SuccessfulAuthentication;

    /// <summary>
    /// Occurs once a final result has been decided-upon, and where that result is that authentication is a failure.
    /// </summary>
    public event EventHandler<AuthenticationStepEventArgs<TRequest>> FailedAuthentication;

    #endregion

    #region methods

    /// <summary>
    /// Creates the <see cref="IPasswordAuthenticationRequest"/>.
    /// </summary>
    /// <returns>The request.</returns>
    /// <param name="enteredPassword">Entered password.</param>
    public virtual TRequest CreateRequest(IPassword enteredPassword)
    {
      return requestFactory.CreateRequest(enteredPassword);
    }

    /// <summary>
    /// Retrieves the stored credentials from a data-store.
    /// </summary>
    /// <param name="request">Request.</param>
    public virtual void RetrieveStoredCredentials(ref TRequest request)
    {
      request.StoredCredentials = GetStoredCredentials(request);

      if(request.StoredCredentials == null)
      {
        request.Result = GetCannotFindCredentialsResult(request);
      }
    }

    /// <summary>
    /// Retrieves the deserialized credentials using a serializer.
    /// </summary>
    /// <param name="request">Request.</param>
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

    /// <summary>
    /// Retrieves the verifier based upon the current request.
    /// </summary>
    /// <param name="request">Request.</param>
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

    /// <summary>
    /// Performs the verification of the password.
    /// </summary>
    /// <param name="request">Request.</param>
    public virtual void PerformVerification(ref TRequest request)
    {
      if(request.Verifier == null)
      {
        request.PasswordVerified = false;
        return;
      }

      request.PasswordVerified = VerifyPassword(request);
    }

    /// <summary>
    /// Determines the final result of the authentication attempt
    /// </summary>
    /// <param name="request">Request.</param>
    public virtual void DetermineResult(ref TRequest request)
    {
      if(request.Result != null)
      {
        return;
      }

      request.Result = GetVerificationResult(request);
    }

    /// <summary>
    /// Gets the verifier from a factory service.
    /// </summary>
    /// <returns>The verifier.</returns>
    /// <param name="request">Request.</param>
    public virtual IPasswordVerifier GetVerifier(TRequest request)
    {
      return verifierFactory.GetVerifier(request.CredentialsObject);
    }

    /// <summary>
    /// Gets the stored credentials from a repository.
    /// </summary>
    /// <returns>The stored credentials.</returns>
    /// <param name="request">Request.</param>
    public virtual IStoredCredentials GetStoredCredentials(TRequest request)
    {
      return repository.GetStoredCredentials(request.EnteredCredentials);
    }

    /// <summary>
    /// Makes use of the selected verifier to verify the credentials.
    /// </summary>
    /// <returns><c>true</c>, if password was verified successfully, <c>false</c> otherwise.</returns>
    /// <param name="request">Request.</param>
    public virtual bool VerifyPassword(TRequest request)
    {
      return request.Verifier.Verify(request.EnteredCredentials, request.CredentialsObject);
    }

    /// <summary>
    /// Gets an authentication result indicating that the credentials (user account) could not be found.
    /// </summary>
    /// <returns>An authentication result.</returns>
    /// <param name="request">Request.</param>
    public virtual IAuthenticationResult GetCannotFindCredentialsResult(TRequest request)
    {
      return new AuthenticationResult(false, false);
    }

    /// <summary>
    /// Gets an authentication result indicating that no verifier could be created from the credentials.
    /// </summary>
    /// <returns>An authentication result.</returns>
    /// <param name="request">Request.</param>
    public virtual IAuthenticationResult GetCannotCreateVerifierResult(TRequest request)
    {
      return new AuthenticationResult(false, true);
    }

    /// <summary>
    /// Gets an authentication result based upon the current state of the request (whether or not the password is verified).
    /// </summary>
    /// <returns>An authentication result.</returns>
    /// <param name="request">Request.</param>
    public virtual IAuthenticationResult GetVerificationResult(TRequest request)
    {
      return new AuthenticationResult(request.PasswordVerified, false);
    }

    #endregion

    #region event invokers

    /// <summary>
    /// Invokes the <see cref="BeforeGetStoredCredentials"/> event.
    /// </summary>
    /// <param name="request">Request.</param>
    protected virtual void OnBeforeGetStoredCredentials(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      BeforeGetStoredCredentials?.Invoke(this, args);
    }

    /// <summary>
    /// Invokes the <see cref="BeforeVerifyPassword"/> event.
    /// </summary>
    /// <param name="request">Request.</param>
    protected virtual void OnBeforeVerifyPassword(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      BeforeVerifyPassword?.Invoke(this, args);
    }

    /// <summary>
    /// Invokes the <see cref="AfterVerifyPassword"/> event.
    /// </summary>
    /// <param name="request">Request.</param>
    protected virtual void OnAfterVerifyPassword(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      AfterVerifyPassword?.Invoke(this, args);
    }

    /// <summary>
    /// Invokes the <see cref="SuccessfulAuthentication"/> event.
    /// </summary>
    /// <param name="request">Request.</param>
    protected virtual void OnSuccessfulAuthentication(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      SuccessfulAuthentication?.Invoke(this, args);
    }

    /// <summary>
    /// Invokes the <see cref="FailedAuthentication"/> event.
    /// </summary>
    /// <param name="request">Request.</param>
    protected virtual void OnFailedAuthentication(TRequest request)
    {
      var args = new AuthenticationStepEventArgs<TRequest>(request);
      FailedAuthentication?.Invoke(this, args);
    }

    /// <summary>
    /// Invokes a suitable success or failure event.
    /// </summary>
    /// <param name="request">Request.</param>
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

    /// <summary>
    /// Initializes a new instance of the <see cref="T:PasswordAuthenticationService{TRequest}"/> class.
    /// </summary>
    /// <param name="requestFactory">Request factory.</param>
    /// <param name="repository">Repository.</param>
    /// <param name="verifierFactory">Verifier factory.</param>
    /// <param name="serializer">Serializer.</param>
    public PasswordAuthenticationService(IStoredCredentialsRepository repository,
                                         IPasswordVerifierFactory verifierFactory = null,
                                         IRequestFactory<TRequest> requestFactory = null,
                                         ICredentialsSerializer serializer = null)
    {
      if(repository == null)
        throw new ArgumentNullException(nameof(repository));

      this.repository = repository;

      this.verifierFactory = verifierFactory?? new PasswordVerifierFactory();
      this.requestFactory = requestFactory?? new SimpleRequestFactory<TRequest>();
      this.credentialsSerializer = serializer?? new JsonCredentialsSerializer();
    }

    #endregion
  }
}
