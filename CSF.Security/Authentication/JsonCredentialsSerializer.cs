//
// JsonCredentialsSerializer.cs
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
using System.IO;
using System.Text;
using Newtonsoft.Json;

namespace CSF.Security.Authentication
{
  /// <summary>
  /// Implementation of <see cref="ICredentialsSerializer"/> which serializes/deserializes to/from JSON-formatted
  /// strings.
  /// </summary>
  public class JsonCredentialsSerializer : ICredentialsSerializer
  {
    /// <summary>
    /// Deserialize the specified serialized credentials string.
    /// </summary>
    /// <param name="credentials">Credentials.</param>
    public object Deserialize(string credentials)
    {
      if(credentials == null)
      {
        throw new ArgumentNullException(nameof(credentials));
      }

      var parts = credentials.Split(new [] { ':' }, 2);
      if(parts.Length != 2)
      {
        throw new FormatException("Credentials string must contain a type name, followed by a colon and then a JSON-formatted serialized object.");
      }

      var typeName = parts[0];
      var jsonObject = parts[1];

      var type = GetType(typeName);

      return GetDeserializedCredentials(jsonObject, type);
    }

    /// <summary>
    /// Serialize the specified credentials to a string.
    /// </summary>
    /// <param name="credentials">Credentials.</param>
    /// <typeparam name="TCredentials">The 1st type parameter.</typeparam>
    public string Serialize<TCredentials>(TCredentials credentials)
    {
      if(ReferenceEquals(credentials, null))
      {
        throw new ArgumentNullException(nameof(credentials));
      }

      var typeName = GetFullTypeName(typeof(TCredentials));
      var serialized = GetSerializedCredentials(credentials);

      return String.Concat(typeName, ":", serialized);
    }

    string GetFullTypeName(Type type)
    {
      return String.Concat(type.FullName, ", ", type.Assembly.GetName().Name);
    }

    Type GetType(string name)
    {
      return Type.GetType(name);
    }

    string GetSerializedCredentials(object credentials)
    {
      var serializer = GetSerializer();
      var output = new StringBuilder();

      using(var writer = new StringWriter(output))
      {
        serializer.Serialize(writer, credentials);
        writer.Flush();
      }

      return output.ToString();
    }

    object GetDeserializedCredentials(string credentials, Type type)
    {
      var serializer = GetSerializer();

      using(var reader = new StringReader(credentials))
      {
        return serializer.Deserialize(reader, type);
      }
    }

    JsonSerializer GetSerializer()
    {
      return JsonSerializer.CreateDefault();
    }
  }
}
