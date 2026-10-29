package com.hanzala.fortress.vault

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/**
 * §9: JSON exactly as Swift's `JSONEncoder` writes it with `.sortedKeys`
 * (compact, keys in byte order, raw UTF-8, `\/` only where Swift escapes
 * slashes), plus strict typed readers over parsed JSON.
 */
object SwiftJson {
    fun parse(bytes: ByteArray): JsonObject {
        val element = try {
            Json.parseToJsonElement(bytes.toString(Charsets.UTF_8))
        } catch (e: SerializationException) {
            throw VaultFormatException("malformed JSON")
        } catch (e: IllegalArgumentException) {
            throw VaultFormatException("malformed JSON")
        }
        return element as? JsonObject ?: throw VaultFormatException("JSON is not an object")
    }

    fun encode(value: JsonElement, escapeSlashes: Boolean): ByteArray {
        val out = StringBuilder()
        write(value, escapeSlashes, out)
        return out.toString().toByteArray(Charsets.UTF_8)
    }

    private fun write(value: JsonElement, escapeSlashes: Boolean, out: StringBuilder) {
        when (value) {
            is JsonObject -> {
                out.append('{')
                val keys = value.keys.sortedWith { a, b -> compareBytes(a, b) }
                keys.forEachIndexed { i, key ->
                    if (i > 0) out.append(',')
                    writeString(key, escapeSlashes, out)
                    out.append(':')
                    write(value.getValue(key), escapeSlashes, out)
                }
                out.append('}')
            }
            is JsonArray -> {
                out.append('[')
                value.forEachIndexed { i, item ->
                    if (i > 0) out.append(',')
                    write(item, escapeSlashes, out)
                }
                out.append(']')
            }
            JsonNull -> throw VaultFormatException("null is never written")
            is JsonPrimitive ->
                if (value.isString) writeString(value.content, escapeSlashes, out) else out.append(value.content)
        }
    }

    private fun compareBytes(a: String, b: String): Int {
        val x = a.toByteArray(Charsets.UTF_8)
        val y = b.toByteArray(Charsets.UTF_8)
        for (i in 0 until minOf(x.size, y.size)) {
            val d = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return x.size - y.size
    }

    private fun writeString(text: String, escapeSlashes: Boolean, out: StringBuilder) {
        out.append('"')
        for (c in text) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '/' && escapeSlashes -> out.append("\\/")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c == '\b' -> out.append("\\b")
                c == '\u000c' -> out.append("\\f")
                c.code < 0x20 -> out.append("\\u00").append(String.format(java.util.Locale.ROOT, "%02x", c.code))
                else -> out.append(c)
            }
        }
        out.append('"')
    }
}

/** Strict typed access to a parsed JSON object; any mismatch is a format error. */
internal class JsonFields(private val obj: JsonObject, private val what: String) {
    fun has(key: String) = obj.containsKey(key)

    fun raw(key: String): JsonElement? = obj[key]

    private fun primitive(key: String): JsonPrimitive =
        obj[key] as? JsonPrimitive ?: throw VaultFormatException("$what.$key missing")

    fun string(key: String): String {
        val p = primitive(key)
        if (!p.isString) throw VaultFormatException("$what.$key is not a string")
        return p.content
    }

    /** A non-negative integer (Swift UInt32/UInt64/Int fields; values above Long.MAX_VALUE are refused). */
    fun unsigned(key: String): Long {
        val p = primitive(key)
        val v = if (p.isString) null else p.longOrNull
        if (v == null || v < 0) throw VaultFormatException("$what.$key is not a non-negative integer")
        return v
    }

    fun bool(key: String): Boolean {
        val p = primitive(key)
        return (if (p.isString) null else p.booleanOrNull) ?: throw VaultFormatException("$what.$key is not a boolean")
    }

    fun uuid(key: String) = Uuids.parse(string(key))

    fun bytes(key: String) = Codings.unbase64(string(key))

    fun date(key: String) = Codings.parseDate(string(key))

    fun obj(key: String) = JsonFields(obj[key] as? JsonObject ?: throw VaultFormatException("$what.$key missing"), "$what.$key")

    /** A required array; [optional] treats a missing key as empty, as Swift does for some fields. */
    fun array(key: String, optional: Boolean = false): JsonArray {
        val v = obj[key] ?: if (optional) return JsonArray(emptyList()) else throw VaultFormatException("$what.$key missing")
        return v as? JsonArray ?: throw VaultFormatException("$what.$key is not an array")
    }

    fun objects(key: String, optional: Boolean = false): List<JsonFields> =
        array(key, optional).map { JsonFields(it as? JsonObject ?: throw VaultFormatException("$what.$key item"), "$what.$key[]") }

    fun strings(key: String, optional: Boolean = false): List<String> =
        array(key, optional).map {
            val p = it as? JsonPrimitive
            if (p == null || !p.isString) throw VaultFormatException("$what.$key item is not a string")
            p.content
        }
}
