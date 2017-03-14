//
// PasswordAuthenticationRequest.cs
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
  public class PasswordAuthenticationRequest<TEntered, TStored, TResult> : IPasswordAuthenticationRequest
    where TEntered : IEnteredPassword
    where TStored : IStoredCredentials
    where TResult : IAuthenticationResult
  {
    #region properties

    public TEntered EnteredCredentials { get; set; }

    public TStored StoredCredentials { get; set; }

    public object CredentialsObject { get; set; }

    public bool PasswordVerified { get; set; }

    public TResult Result { get; set; }

    public IPasswordVerifier Verifier { get; set; }

    #endregion

    #region explicit interface implementation

    IEnteredPassword IPasswordAuthenticationRequest.EnteredCredentials
    {
      get { return EnteredCredentials; }
      set { EnteredCredentials = (TEntered) value; }
    }

    IStoredCredentials IPasswordAuthenticationRequest.StoredCredentials
    {
      get { return StoredCredentials; }
      set { StoredCredentials = (TStored) value; }
    }

    IAuthenticationResult IPasswordAuthenticationRequest.Result
    {
      get { return Result; }
      set { Result = (TResult) value; }
    }

    #endregion
  }
}
