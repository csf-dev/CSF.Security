﻿//
// EnteredPasswordBase.cs
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
  /// Represents the credentials that a user has entered at a login prompt.  Includes a password.
  /// </summary>
  public class CredentialsWithPassword : IPassword
  {
    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    /// <value>The password.</value>
    public string Password
    {
      get;
      set;
    }

    /// <summary>
    /// Gets the password as a byte array.
    /// </summary>
    /// <returns>The password as byte array.</returns>
    public byte[] GetPasswordAsByteArray()
    {
      if(Password == null)
      {
        return null;
      }

      return System.Text.Encoding.UTF8.GetBytes(Password);
    }
  }
}
