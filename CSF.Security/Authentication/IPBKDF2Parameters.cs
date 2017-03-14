//
// IPBKDF2Parameters.cs
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
  /// Represents the relevant parameters for the PBKDF2 hashing algorithm.
  /// </summary>
  public interface IPBKDF2Parameters
  {
    /// <summary>
    /// Gets the length for newly-created PBKDF2 keys.
    /// </summary>
    /// <returns>The key length.</returns>
    int GetKeyLength();

    /// <summary>
    /// Gets the length for newly-created PBKDF2 salts.
    /// </summary>
    /// <returns>The salt length.</returns>
    int GetSaltLength();

    /// <summary>
    /// Gets the iteration count used for the PBKDF2 algorithm.
    /// </summary>
    int GetIterationCount();
  }
}
