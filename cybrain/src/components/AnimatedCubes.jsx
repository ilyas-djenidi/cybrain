import React, { useEffect, useRef } from 'react';

const AnimatedCubes = () => {
    const containerRef = useRef();

    // Cube configurations — position, size, speed, color
    const cubes = [
        {
            id: 1,
            size: 60,
            x: 10, y: 20,
            rotateX: 45, rotateY: 45,
            speedX: 0.8, speedY: 0.6,
            color: 'rgba(0,245,212,0.15)',
            border: 'rgba(0,245,212,0.4)',
            delay: 0,
        },
        {
            id: 2,
            size: 40,
            x: 75, y: 15,
            rotateX: 20, rotateY: 60,
            speedX: -0.6, speedY: 0.9,
            color: 'rgba(168,85,247,0.12)',
            border: 'rgba(168,85,247,0.4)',
            delay: 0.5,
        },
        {
            id: 3,
            size: 80,
            x: 55, y: 60,
            rotateX: 60, rotateY: 30,
            speedX: 0.5, speedY: -0.7,
            color: 'rgba(0,245,212,0.08)',
            border: 'rgba(0,245,212,0.25)',
            delay: 1,
        },
        {
            id: 4,
            size: 35,
            x: 20, y: 70,
            rotateX: 30, rotateY: 45,
            speedX: -0.9, speedY: 0.5,
            color: 'rgba(168,85,247,0.15)',
            border: 'rgba(168,85,247,0.35)',
            delay: 1.5,
        },
        {
            id: 5,
            size: 55,
            x: 85, y: 55,
            rotateX: 50, rotateY: 20,
            speedX: 0.7, speedY: -0.8,
            color: 'rgba(0,180,255,0.10)',
            border: 'rgba(0,180,255,0.30)',
            delay: 0.3,
        },
        {
            id: 6,
            size: 25,
            x: 40, y: 85,
            rotateX: 15, rotateY: 55,
            speedX: -0.5, speedY: -0.6,
            color: 'rgba(0,245,212,0.12)',
            border: 'rgba(0,245,212,0.30)',
            delay: 2,
        },
        {
            id: 7,
            size: 45,
            x: 5, y: 50,
            rotateX: 70, rotateY: 40,
            speedX: 1.0, speedY: 0.4,
            color: 'rgba(168,85,247,0.10)',
            border: 'rgba(168,85,247,0.25)',
            delay: 0.8,
        },
        {
            id: 8,
            size: 30,
            x: 65, y: 30,
            rotateX: 25, rotateY: 65,
            speedX: -0.7, speedY: 1.0,
            color: 'rgba(0,245,212,0.18)',
            border: 'rgba(0,245,212,0.45)',
            delay: 1.2,
        },
    ];

    return (
        <div
            ref={containerRef}
            className="absolute inset-0 overflow-hidden"
            style={{ perspective: '1000px' }}
        >
            {cubes.map((cube) => (
                <div
                    key={cube.id}
                    className="absolute"
                    style={{
                        left:   `${cube.x}%`,
                        top:    `${cube.y}%`,
                        width:  `${cube.size}px`,
                        height: `${cube.size}px`,
                        transformStyle: 'preserve-3d',
                        animation: `
                            float-cube-${cube.id}
                            ${8 + cube.id * 1.5}s
                            ease-in-out infinite alternate,
                            rotate-cube-${cube.id}
                            ${12 + cube.id * 2}s
                            linear infinite
                        `,
                        animationDelay: `${cube.delay}s`,
                    }}
                >
                    {/* Cube faces */}
                    {['front','back','left',
                      'right','top','bottom'].map(face => (
                        <div
                            key={face}
                            style={{
                                position: 'absolute',
                                width:    '100%',
                                height:   '100%',
                                background: cube.color,
                                border: `1px solid ${cube.border}`,
                                backdropFilter: 'blur(2px)',
                                transform: (
                                    face === 'front'
                                        ? `translateZ(${cube.size/2}px)`
                                    : face === 'back'
                                        ? `translateZ(-${cube.size/2}px) rotateY(180deg)`
                                    : face === 'left'
                                        ? `translateX(-${cube.size/2}px) rotateY(-90deg)`
                                    : face === 'right'
                                        ? `translateX(${cube.size/2}px) rotateY(90deg)`
                                    : face === 'top'
                                        ? `translateY(-${cube.size/2}px) rotateX(90deg)`
                                    : `translateY(${cube.size/2}px) rotateX(-90deg)`
                                ),
                            }}
                        />
                    ))}
                </div>
            ))}

            {/* CSS Keyframes injected */}
            <style>{`
                /* Float animations — each cube moves differently */
                @keyframes float-cube-1 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(30px, -40px); }
                }
                @keyframes float-cube-2 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(-25px, 35px); }
                }
                @keyframes float-cube-3 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(40px, 25px); }
                }
                @keyframes float-cube-4 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(-35px, -30px); }
                }
                @keyframes float-cube-5 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(20px, -45px); }
                }
                @keyframes float-cube-6 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(-40px, 20px); }
                }
                @keyframes float-cube-7 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(35px, 30px); }
                }
                @keyframes float-cube-8 {
                    0%   { transform: translate(0px, 0px); }
                    100% { transform: translate(-20px, -35px); }
                }

                /* Rotation animations */
                @keyframes rotate-cube-1 {
                    from { transform: rotateX(0deg) rotateY(0deg) rotateZ(0deg); }
                    to   { transform: rotateX(360deg) rotateY(360deg) rotateZ(180deg); }
                }
                @keyframes rotate-cube-2 {
                    from { transform: rotateX(0deg) rotateY(0deg); }
                    to   { transform: rotateX(-360deg) rotateY(360deg); }
                }
                @keyframes rotate-cube-3 {
                    from { transform: rotateX(45deg) rotateY(0deg); }
                    to   { transform: rotateX(45deg) rotateY(360deg); }
                }
                @keyframes rotate-cube-4 {
                    from { transform: rotateX(0deg) rotateZ(0deg); }
                    to   { transform: rotateX(360deg) rotateZ(360deg); }
                }
                @keyframes rotate-cube-5 {
                    from { transform: rotateY(0deg) rotateZ(0deg); }
                    to   { transform: rotateY(-360deg) rotateZ(180deg); }
                }
                @keyframes rotate-cube-6 {
                    from { transform: rotateX(20deg) rotateY(0deg); }
                    to   { transform: rotateX(20deg) rotateY(-360deg); }
                }
                @keyframes rotate-cube-7 {
                    from { transform: rotateX(0deg) rotateY(45deg) rotateZ(0deg); }
                    to   { transform: rotateX(360deg) rotateY(45deg) rotateZ(360deg); }
                }
                @keyframes rotate-cube-8 {
                    from { transform: rotateX(30deg) rotateY(0deg) rotateZ(0deg); }
                    to   { transform: rotateX(-30deg) rotateY(360deg) rotateZ(180deg); }
                }

                /* Respect reduced motion */
                @media (prefers-reduced-motion: reduce) {
                    [style*="float-cube"],
                    [style*="rotate-cube"] {
                        animation: none !important;
                    }
                }
            `}</style>
        </div>
    );
};

export default AnimatedCubes;
