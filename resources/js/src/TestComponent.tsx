import React, { useEffect } from 'react';

const TestComponent = () => {
    useEffect(() => {
        console.log('TestComponent mounted');
    }, []);

    return (
        <div>
            Hello from TestComponent!
        </div>
    );
};

export default TestComponent;