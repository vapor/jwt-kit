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
