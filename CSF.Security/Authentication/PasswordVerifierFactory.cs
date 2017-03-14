//
// PasswordVerifierFactory.cs
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
using System.Collections.Generic;

namespace CSF.Security.Authentication
{
  public class PasswordVerifierFactory : IPasswordVerifierFactory
  {
    readonly Dictionary<Type,Func<object,IPasswordVerifier>> creationFunctions;

    public IDictionary<Type, Func<object, IPasswordVerifier>> CreationFunctions
    {
      get {
        return creationFunctions;
      }
    }

    public IPasswordVerifier GetVerifier(object credentialsObject)
    {
      var creationFunction = GetVerifierFunction(credentialsObject);

      if(creationFunction == null)
      {
        return null;
      }

      return creationFunction(credentialsObject);
    }

    Func<object,IPasswordVerifier> GetVerifierFunction(object credentialsObject)
    {
      if(credentialsObject == null)
      {
        return null;
      }

      var credentialsType = credentialsObject.GetType();
      return GetVerifierFunction(credentialsType);
    }

    Func<object,IPasswordVerifier> GetVerifierFunction(Type credentialsType)
    {
      if(credentialsType == null)
      {
        return null;
      }

      if(CreationFunctions.ContainsKey(credentialsType))
      {
        return CreationFunctions[credentialsType];
      }

      return null;
    }

    public PasswordVerifierFactory()
    {
      creationFunctions = new Dictionary<Type, Func<object, IPasswordVerifier>>();
    }
  }
}
