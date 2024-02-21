import XCTest

func XCTAssertNoThrowAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async {
    do {
        _ = try await expression()
    } catch {
        let msg = error.localizedDescription
        XCTFail("Expression did throw error\(msg.isEmpty ? "" : ": \(msg)")", file: file, line: line)
    }
}

func XCTUnwrapAsync<T>(
    _ expression: @autoclosure () async throws -> T?,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) async throws -> T {
    let result = try await expression()
    return try XCTUnwrap(result, message(), file: file, line: line)
}

func XCTAssertEqualAsync<T>(
    _ expression1: @autoclosure () async throws -> T,
    _ expression2: @autoclosure () async throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) async where T: Equatable {
    do {
        let expr1 = try await expression1(), expr2 = try await expression2()
        return XCTAssertEqual(expr1, expr2, message(), file: file, line: line)
    } catch {
        return XCTAssertEqual(try { () -> Bool in throw error }(), false, message(), file: file, line: line)
    }
}

func XCTAssertNotEqualAsync<T>(
    _ expression1: @autoclosure () async throws -> T,
    _ expression2: @autoclosure () async throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) async where T: Equatable {
    do {
        let expr1 = try await expression1(), expr2 = try await expression2()
        return XCTAssertNotEqual(expr1, expr2, message(), file: file, line: line)
    } catch {
        return XCTAssertNotEqual(try { () -> Bool in throw error }(), true, message(), file: file, line: line)
    }
}

func XCTAssertEqualAsync<T>(
    _ expression1: @autoclosure () async throws -> T,
    _ expression2: @autoclosure () async throws -> T,
    accuracy: T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async where T: Numeric {
    do {
        let expr1 = try await expression1(), expr2 = try await expression2()
        return XCTAssertEqual(expr1, expr2, accuracy: accuracy, message(), file: file, line: line)
    } catch {
        return XCTAssertEqual(try { () -> Bool in throw error }(), false, message(), file: file, line: line)
    }
}

func XCTAssertEqualAsync<T>(
    _ expression1: @autoclosure () async throws -> T,
    _ expression2: @autoclosure () async throws -> T,
    accuracy: T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async where T: FloatingPoint {
    do {
        let expr1 = try await expression1(), expr2 = try await expression2()
        return XCTAssertEqual(expr1, expr2, accuracy: accuracy, message(), file: file, line: line)
    } catch {
        return XCTAssertEqual(try { () -> Bool in throw error }(), false, message(), file: file, line: line)
    }
}

func XCTAssertAsync(
    _ predicate: @autoclosure () async throws -> Bool,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async rethrows {
    let result = try await predicate()
    XCTAssert(result, message(), file: file, line: line)
}

func XCTAssertTrueAsync(
    _ predicate: @autoclosure () async throws -> Bool,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async rethrows {
    let result = try await predicate()
    XCTAssertTrue(result, message(), file: file, line: line)
}

func XCTAssertFalseAsync(
    _ predicate: @autoclosure () async throws -> Bool,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async rethrows {
    let result = try await predicate()
    XCTAssertFalse(result, message(), file: file, line: line)
}

func XCTAssertThrowsErrorAsync<ResultType>(
    _ expression: @autoclosure () async throws -> ResultType,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line,
    _ callback: ((Error) -> Void)? = nil
) async {
    do {
        _ = try await expression()
        XCTFail("Did not throw: \(message())", file: file, line: line)
    } catch {
        callback?(error)
    }
}

func XCTAssertNilAsync(
    _ expression: @autoclosure () async throws -> Any?,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async rethrows {
    let result = try await expression()
    XCTAssertNil(result, message(), file: file, line: line)
}

func XCTAssertNotNilAsync(
    _ expression: @autoclosure () async throws -> Any?,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath, line: UInt = #line
) async rethrows {
    let result = try await expression()
    XCTAssertNotNil(result, message(), file: file, line: line)
}
