//
// AuthenticationService.cs
//
// Author:
//       Craig Fowler <craig@craigfowler.me.uk>
//
// Copyright (c) 2016 Craig Fowler
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

namespace CSF.Security
{
  /// <summary>
  /// Abstract base type for an authentication service.
  /// </summary>
  public class AuthenticationService<TEnteredCredentials,TStoredCredentials>
    : IAuthenticationService<TEnteredCredentials>
  {
    #region fields

    readonly ICredentialsRepository<TEnteredCredentials,TStoredCredentials> credentialsRepository;
    readonly Func<TEnteredCredentials,TStoredCredentials,ICredentialVerifier<TEnteredCredentials,TStoredCredentials>> verifierFactory;

    #endregion

    #region fields

    /// <summary>
    /// Gets the credentials repository.
    /// </summary>
    /// <value>The credentials repository.</value>
    protected ICredentialsRepository<TEnteredCredentials,TStoredCredentials> CredentialsRepository
      => credentialsRepository;

    /// <summary>
    /// Gets the credentials verifier.
    /// </summary>
    /// <value>The credentials verifier.</value>
    protected Func<TEnteredCredentials,TStoredCredentials,ICredentialVerifier<TEnteredCredentials,TStoredCredentials>> VerifierFactory
      => verifierFactory;

    #endregion

    #region methods

    /// <summary>
    /// Attempts authentication using the given credentials.
    /// </summary>
    /// <param name="enteredCredentials">Entered credentials.</param>
    public virtual AuthenticationResult Authenticate(TEnteredCredentials enteredCredentials)
    {
      if(ReferenceEquals(enteredCredentials, null))
      {
        throw new ArgumentNullException(nameof(enteredCredentials));
      }

      var storedCredentials = CredentialsRepository.GetStoredCredentials(enteredCredentials);
      if(ReferenceEquals(storedCredentials, null))
      {
        return new AuthenticationResult(false, false);
      }

      var verifier = GetVerifier(enteredCredentials, storedCredentials);
      var verified = verifier.Verify(enteredCredentials, storedCredentials);

      return new AuthenticationResult(true, verified);
    }

    AuthenticationResult IAuthenticationService.Authenticate(object enteredCredentials)
    {
      return Authenticate((TEnteredCredentials) enteredCredentials);
    }

    /// <summary>
    /// Gets the credentials verifier from the entered and stored credentials.
    /// </summary>
    /// <returns>The verifier.</returns>
    /// <param name="enteredCredentials">Entered credentials.</param>
    /// <param name="storedCredentials">Stored credentials.</param>
    protected virtual ICredentialVerifier<TEnteredCredentials,TStoredCredentials> GetVerifier(TEnteredCredentials enteredCredentials,
                                                                                              TStoredCredentials storedCredentials)
    {
      return VerifierFactory(enteredCredentials, storedCredentials);
    }

    #endregion

    #region constructor

    /// <summary>
    /// Initializes a new instance of the
    /// <see cref="T:AuthenticationService{TEnteredCredentials,TStoredCredentials}"/> class.
    /// </summary>
    /// <param name="repository">Credentials repository.</param>
    /// <param name="verifierFactory">A delegate factory which creates an instance of a credentials verifier.</param>
    public AuthenticationService(ICredentialsRepository<TEnteredCredentials,TStoredCredentials> repository,
                                 Func<TEnteredCredentials,TStoredCredentials,ICredentialVerifier<TEnteredCredentials,TStoredCredentials>> verifierFactory)
    {
      if(repository == null)
      {
        throw new ArgumentNullException(nameof(repository));
      }
      if(verifierFactory == null)
      {
        throw new ArgumentNullException(nameof(verifierFactory));
      }

      this.credentialsRepository = repository;
      this.verifierFactory = verifierFactory;
    }

    /// <summary>
    /// Initializes a new instance of the
    /// <see cref="T:AuthenticationService{TEnteredCredentials,TStoredCredentials}"/> class.
    /// </summary>
    /// <param name="repository">Credentials repository.</param>
    /// <param name="verifier">Credentials verifier.</param>
    public AuthenticationService(ICredentialsRepository<TEnteredCredentials,TStoredCredentials> repository,
                                 ICredentialVerifier<TEnteredCredentials,TStoredCredentials> verifier)
    {
      if(repository == null)
      {
        throw new ArgumentNullException(nameof(repository));
      }
      if(verifier == null)
      {
        throw new ArgumentNullException(nameof(verifier));
      }

      this.credentialsRepository = repository;
      this.verifierFactory = (TEnteredCredentials entered, TStoredCredentials stored) => verifier;
    }

    #endregion
  }
}

