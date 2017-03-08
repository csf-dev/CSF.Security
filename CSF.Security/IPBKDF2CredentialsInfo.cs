//
// PBKDF2CredentialsCredentialsInfo.cs
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
namespace CSF.Security
{
  /// <summary>
  /// Interface to represent credentials information used by the PBKDF2 verification mechanism.
  /// </summary>
  public interface IPBKDF2CredentialsInfo : ICredentialsWithPassword
  {
    /// <summary>
    /// Gets the desired byte length of the generated salt.
    /// </summary>
    /// <value>The length of the salt.</value>
    int SaltLength { get; }

    /// <summary>
    /// Gets the desired iteration count.
    /// </summary>
    /// <value>The iteration count.</value>
    int IterationCount { get; }

    /// <summary>
    /// Gets the desired byte-length of the generated key.
    /// </summary>
    /// <value>The length of the key.</value>
    int KeyLength { get; }
  }
}
