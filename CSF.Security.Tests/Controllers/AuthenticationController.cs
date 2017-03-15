//
// AuthenticationController.cs
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

namespace CSF.Security.Tests.Controllers
{
  public class AuthenticationController
  {
    IAuthenticationResult authenticationResult;
    bool useSuccessListener, useFailureListener, listenerTriggered;

    public IAuthenticationResult AuthenticationResult => authenticationResult;

    public bool ListenerWasTriggered => listenerTriggered;

    public void AttemptLogin(string username, string password, IStoredCredentialsRepository repo)
    {
      var credentials = new UsernameAndPassword {
        Username = username,
        Password = password
      };

      var authenticationService = GetAuthenticationService(repo);
      authenticationResult = authenticationService.Authenticate(credentials);
    }

    public void SetupSuccessListener()
    {
      useSuccessListener = true;
    }

    public void SetupFailureListener()
    {
      useFailureListener = true;
    }

    IPasswordAuthenticationService GetAuthenticationService(IStoredCredentialsRepository repo)
    {
      var output = new PasswordAuthenticationService<AuthenticationRequest>(repo);

      if(useSuccessListener)
      {
        output.SuccessfulAuthentication += (sender, e) => {
          listenerTriggered = true;
        };
      }
      else if(useFailureListener)
      {
        output.FailedAuthentication += (sender, e) => {
          listenerTriggered = true;
        };
      }

      return output;
    }
  }
}
